rule TTP_XOR_QUAD_CurrentVersionRun_f3a1 {
  strings:
    $key_f3a1 = { a0 ce [2] 84 c0 [2] af ec [2] 81 ce [2] 95 d5 [2] 9a cf [2] 84 d2 [2] 86 d3 [2] 9d d5 [2] 81 d2 [2] 9d fd }

  condition:
    any of them
}