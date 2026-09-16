rule TTP_XOR_QUAD_CurrentVersionRun_23a1 {
  strings:
    $key_23a1 = { 70 ce [2] 54 c0 [2] 7f ec [2] 51 ce [2] 45 d5 [2] 4a cf [2] 54 d2 [2] 56 d3 [2] 4d d5 [2] 51 d2 [2] 4d fd }

  condition:
    any of them
}