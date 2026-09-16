rule TTP_XOR_QUAD_CurrentVersionRun_4ea1 {
  strings:
    $key_4ea1 = { 1d ce [2] 39 c0 [2] 12 ec [2] 3c ce [2] 28 d5 [2] 27 cf [2] 39 d2 [2] 3b d3 [2] 20 d5 [2] 3c d2 [2] 20 fd }

  condition:
    any of them
}