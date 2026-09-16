rule TTP_XOR_QUAD_CurrentVersionRun_a5b2 {
  strings:
    $key_a5b2 = { f6 dd [2] d2 d3 [2] f9 ff [2] d7 dd [2] c3 c6 [2] cc dc [2] d2 c1 [2] d0 c0 [2] cb c6 [2] d7 c1 [2] cb ee }

  condition:
    any of them
}