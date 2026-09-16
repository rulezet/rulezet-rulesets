rule TTP_XOR_QUAD_CurrentVersionRun_f5a1 {
  strings:
    $key_f5a1 = { a6 ce [2] 82 c0 [2] a9 ec [2] 87 ce [2] 93 d5 [2] 9c cf [2] 82 d2 [2] 80 d3 [2] 9b d5 [2] 87 d2 [2] 9b fd }

  condition:
    any of them
}