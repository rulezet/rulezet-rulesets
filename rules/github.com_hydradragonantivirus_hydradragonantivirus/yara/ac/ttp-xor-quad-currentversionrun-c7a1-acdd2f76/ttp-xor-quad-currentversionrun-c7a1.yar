rule TTP_XOR_QUAD_CurrentVersionRun_c7a1 {
  strings:
    $key_c7a1 = { 94 ce [2] b0 c0 [2] 9b ec [2] b5 ce [2] a1 d5 [2] ae cf [2] b0 d2 [2] b2 d3 [2] a9 d5 [2] b5 d2 [2] a9 fd }

  condition:
    any of them
}