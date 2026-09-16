rule TTP_XOR_QUAD_CurrentVersionRun_1ea1 {
  strings:
    $key_1ea1 = { 4d ce [2] 69 c0 [2] 42 ec [2] 6c ce [2] 78 d5 [2] 77 cf [2] 69 d2 [2] 6b d3 [2] 70 d5 [2] 6c d2 [2] 70 fd }

  condition:
    any of them
}