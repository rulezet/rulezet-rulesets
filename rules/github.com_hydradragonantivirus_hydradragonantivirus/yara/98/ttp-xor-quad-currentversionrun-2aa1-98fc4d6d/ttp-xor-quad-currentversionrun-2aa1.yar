rule TTP_XOR_QUAD_CurrentVersionRun_2aa1 {
  strings:
    $key_2aa1 = { 79 ce [2] 5d c0 [2] 76 ec [2] 58 ce [2] 4c d5 [2] 43 cf [2] 5d d2 [2] 5f d3 [2] 44 d5 [2] 58 d2 [2] 44 fd }

  condition:
    any of them
}