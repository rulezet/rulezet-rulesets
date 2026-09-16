rule TTP_XOR_QUAD_CurrentVersionRun_79a1 {
  strings:
    $key_79a1 = { 2a ce [2] 0e c0 [2] 25 ec [2] 0b ce [2] 1f d5 [2] 10 cf [2] 0e d2 [2] 0c d3 [2] 17 d5 [2] 0b d2 [2] 17 fd }

  condition:
    any of them
}