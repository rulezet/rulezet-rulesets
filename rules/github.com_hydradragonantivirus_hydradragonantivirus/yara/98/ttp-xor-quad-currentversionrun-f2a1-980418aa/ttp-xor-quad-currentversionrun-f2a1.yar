rule TTP_XOR_QUAD_CurrentVersionRun_f2a1 {
  strings:
    $key_f2a1 = { a1 ce [2] 85 c0 [2] ae ec [2] 80 ce [2] 94 d5 [2] 9b cf [2] 85 d2 [2] 87 d3 [2] 9c d5 [2] 80 d2 [2] 9c fd }

  condition:
    any of them
}