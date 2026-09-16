rule TTP_XOR_QUAD_CurrentVersionRun_07a1 {
  strings:
    $key_07a1 = { 54 ce [2] 70 c0 [2] 5b ec [2] 75 ce [2] 61 d5 [2] 6e cf [2] 70 d2 [2] 72 d3 [2] 69 d5 [2] 75 d2 [2] 69 fd }

  condition:
    any of them
}