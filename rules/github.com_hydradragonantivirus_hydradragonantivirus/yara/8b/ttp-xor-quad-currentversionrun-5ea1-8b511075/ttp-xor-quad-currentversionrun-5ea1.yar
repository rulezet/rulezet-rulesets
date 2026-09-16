rule TTP_XOR_QUAD_CurrentVersionRun_5ea1 {
  strings:
    $key_5ea1 = { 0d ce [2] 29 c0 [2] 02 ec [2] 2c ce [2] 38 d5 [2] 37 cf [2] 29 d2 [2] 2b d3 [2] 30 d5 [2] 2c d2 [2] 30 fd }

  condition:
    any of them
}