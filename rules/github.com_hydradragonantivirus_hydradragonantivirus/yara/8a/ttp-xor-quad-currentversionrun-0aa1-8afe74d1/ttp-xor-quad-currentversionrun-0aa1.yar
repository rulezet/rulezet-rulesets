rule TTP_XOR_QUAD_CurrentVersionRun_0aa1 {
  strings:
    $key_0aa1 = { 59 ce [2] 7d c0 [2] 56 ec [2] 78 ce [2] 6c d5 [2] 63 cf [2] 7d d2 [2] 7f d3 [2] 64 d5 [2] 78 d2 [2] 64 fd }

  condition:
    any of them
}