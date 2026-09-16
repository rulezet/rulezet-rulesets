rule TTP_XOR_QUAD_CurrentVersionRun_47a1 {
  strings:
    $key_47a1 = { 14 ce [2] 30 c0 [2] 1b ec [2] 35 ce [2] 21 d5 [2] 2e cf [2] 30 d2 [2] 32 d3 [2] 29 d5 [2] 35 d2 [2] 29 fd }

  condition:
    any of them
}