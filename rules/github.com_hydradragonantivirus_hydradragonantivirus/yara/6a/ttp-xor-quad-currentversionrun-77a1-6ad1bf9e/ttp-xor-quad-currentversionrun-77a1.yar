rule TTP_XOR_QUAD_CurrentVersionRun_77a1 {
  strings:
    $key_77a1 = { 24 ce [2] 00 c0 [2] 2b ec [2] 05 ce [2] 11 d5 [2] 1e cf [2] 00 d2 [2] 02 d3 [2] 19 d5 [2] 05 d2 [2] 19 fd }

  condition:
    any of them
}