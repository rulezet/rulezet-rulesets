rule TTP_XOR_QUAD_CurrentVersionRun_c5b2 {
  strings:
    $key_c5b2 = { 96 dd [2] b2 d3 [2] 99 ff [2] b7 dd [2] a3 c6 [2] ac dc [2] b2 c1 [2] b0 c0 [2] ab c6 [2] b7 c1 [2] ab ee }

  condition:
    any of them
}