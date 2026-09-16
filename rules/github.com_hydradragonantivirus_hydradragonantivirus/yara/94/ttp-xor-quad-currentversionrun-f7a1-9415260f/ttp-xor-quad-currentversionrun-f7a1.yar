rule TTP_XOR_QUAD_CurrentVersionRun_f7a1 {
  strings:
    $key_f7a1 = { a4 ce [2] 80 c0 [2] ab ec [2] 85 ce [2] 91 d5 [2] 9e cf [2] 80 d2 [2] 82 d3 [2] 99 d5 [2] 85 d2 [2] 99 fd }

  condition:
    any of them
}