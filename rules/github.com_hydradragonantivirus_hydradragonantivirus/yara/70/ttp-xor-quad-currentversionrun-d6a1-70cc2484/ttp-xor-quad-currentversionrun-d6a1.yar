rule TTP_XOR_QUAD_CurrentVersionRun_d6a1 {
  strings:
    $key_d6a1 = { 85 ce [2] a1 c0 [2] 8a ec [2] a4 ce [2] b0 d5 [2] bf cf [2] a1 d2 [2] a3 d3 [2] b8 d5 [2] a4 d2 [2] b8 fd }

  condition:
    any of them
}