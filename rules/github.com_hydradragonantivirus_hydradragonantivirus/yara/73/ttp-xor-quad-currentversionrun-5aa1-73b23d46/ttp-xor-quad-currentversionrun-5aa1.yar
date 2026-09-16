rule TTP_XOR_QUAD_CurrentVersionRun_5aa1 {
  strings:
    $key_5aa1 = { 09 ce [2] 2d c0 [2] 06 ec [2] 28 ce [2] 3c d5 [2] 33 cf [2] 2d d2 [2] 2f d3 [2] 34 d5 [2] 28 d2 [2] 34 fd }

  condition:
    any of them
}