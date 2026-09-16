rule TTP_XOR_QUAD_CurrentVersionRun_63a1 {
  strings:
    $key_63a1 = { 30 ce [2] 14 c0 [2] 3f ec [2] 11 ce [2] 05 d5 [2] 0a cf [2] 14 d2 [2] 16 d3 [2] 0d d5 [2] 11 d2 [2] 0d fd }

  condition:
    any of them
}