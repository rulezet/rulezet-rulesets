rule TTP_XOR_QUAD_CurrentVersionRun_67a1 {
  strings:
    $key_67a1 = { 34 ce [2] 10 c0 [2] 3b ec [2] 15 ce [2] 01 d5 [2] 0e cf [2] 10 d2 [2] 12 d3 [2] 09 d5 [2] 15 d2 [2] 09 fd }

  condition:
    any of them
}