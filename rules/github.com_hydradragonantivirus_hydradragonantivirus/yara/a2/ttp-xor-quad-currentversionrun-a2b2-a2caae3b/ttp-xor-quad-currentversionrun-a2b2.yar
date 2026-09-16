rule TTP_XOR_QUAD_CurrentVersionRun_a2b2 {
  strings:
    $key_a2b2 = { f1 dd [2] d5 d3 [2] fe ff [2] d0 dd [2] c4 c6 [2] cb dc [2] d5 c1 [2] d7 c0 [2] cc c6 [2] d0 c1 [2] cc ee }

  condition:
    any of them
}