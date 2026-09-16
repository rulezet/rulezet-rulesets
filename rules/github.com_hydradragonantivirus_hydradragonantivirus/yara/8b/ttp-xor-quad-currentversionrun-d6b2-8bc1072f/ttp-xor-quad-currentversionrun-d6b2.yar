rule TTP_XOR_QUAD_CurrentVersionRun_d6b2 {
  strings:
    $key_d6b2 = { 85 dd [2] a1 d3 [2] 8a ff [2] a4 dd [2] b0 c6 [2] bf dc [2] a1 c1 [2] a3 c0 [2] b8 c6 [2] a4 c1 [2] b8 ee }

  condition:
    any of them
}