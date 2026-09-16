rule TTP_XOR_QUAD_CurrentVersionRun_c6b2 {
  strings:
    $key_c6b2 = { 95 dd [2] b1 d3 [2] 9a ff [2] b4 dd [2] a0 c6 [2] af dc [2] b1 c1 [2] b3 c0 [2] a8 c6 [2] b4 c1 [2] a8 ee }

  condition:
    any of them
}