rule TTP_XOR_QUAD_CurrentVersionRun_3aa1 {
  strings:
    $key_3aa1 = { 69 ce [2] 4d c0 [2] 66 ec [2] 48 ce [2] 5c d5 [2] 53 cf [2] 4d d2 [2] 4f d3 [2] 54 d5 [2] 48 d2 [2] 54 fd }

  condition:
    any of them
}