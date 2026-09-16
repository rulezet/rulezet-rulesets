rule TTP_XOR_QUAD_CurrentVersionRun_f0a1 {
  strings:
    $key_f0a1 = { a3 ce [2] 87 c0 [2] ac ec [2] 82 ce [2] 96 d5 [2] 99 cf [2] 87 d2 [2] 85 d3 [2] 9e d5 [2] 82 d2 [2] 9e fd }

  condition:
    any of them
}