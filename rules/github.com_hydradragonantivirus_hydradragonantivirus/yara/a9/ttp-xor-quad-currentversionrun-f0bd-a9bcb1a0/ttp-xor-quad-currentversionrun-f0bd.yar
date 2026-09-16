rule TTP_XOR_QUAD_CurrentVersionRun_f0bd {
  strings:
    $key_f0bd = { a3 d2 [2] 87 dc [2] ac f0 [2] 82 d2 [2] 96 c9 [2] 99 d3 [2] 87 ce [2] 85 cf [2] 9e c9 [2] 82 ce [2] 9e e1 }

  condition:
    any of them
}