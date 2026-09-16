rule TTP_XOR_QUAD_CurrentVersionRun_c6a1 {
  strings:
    $key_c6a1 = { 95 ce [2] b1 c0 [2] 9a ec [2] b4 ce [2] a0 d5 [2] af cf [2] b1 d2 [2] b3 d3 [2] a8 d5 [2] b4 d2 [2] a8 fd }

  condition:
    any of them
}