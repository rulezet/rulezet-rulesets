rule TTP_XOR_QUAD_CurrentVersionRun_1ba1 {
  strings:
    $key_1ba1 = { 48 ce [2] 6c c0 [2] 47 ec [2] 69 ce [2] 7d d5 [2] 72 cf [2] 6c d2 [2] 6e d3 [2] 75 d5 [2] 69 d2 [2] 75 fd }

  condition:
    any of them
}