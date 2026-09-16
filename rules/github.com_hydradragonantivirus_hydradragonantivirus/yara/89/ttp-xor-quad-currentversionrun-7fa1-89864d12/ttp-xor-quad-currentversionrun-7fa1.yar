rule TTP_XOR_QUAD_CurrentVersionRun_7fa1 {
  strings:
    $key_7fa1 = { 2c ce [2] 08 c0 [2] 23 ec [2] 0d ce [2] 19 d5 [2] 16 cf [2] 08 d2 [2] 0a d3 [2] 11 d5 [2] 0d d2 [2] 11 fd }

  condition:
    any of them
}