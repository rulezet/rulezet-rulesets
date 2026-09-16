rule TTP_XOR_QUAD_CurrentVersionRun_7aa1 {
  strings:
    $key_7aa1 = { 29 ce [2] 0d c0 [2] 26 ec [2] 08 ce [2] 1c d5 [2] 13 cf [2] 0d d2 [2] 0f d3 [2] 14 d5 [2] 08 d2 [2] 14 fd }

  condition:
    any of them
}