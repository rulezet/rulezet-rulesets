rule TTP_XOR_QUAD_CurrentVersionRun_7ba1 {
  strings:
    $key_7ba1 = { 28 ce [2] 0c c0 [2] 27 ec [2] 09 ce [2] 1d d5 [2] 12 cf [2] 0c d2 [2] 0e d3 [2] 15 d5 [2] 09 d2 [2] 15 fd }

  condition:
    any of them
}