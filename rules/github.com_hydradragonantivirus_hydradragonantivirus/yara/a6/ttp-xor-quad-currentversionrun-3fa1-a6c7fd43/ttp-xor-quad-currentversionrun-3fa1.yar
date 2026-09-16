rule TTP_XOR_QUAD_CurrentVersionRun_3fa1 {
  strings:
    $key_3fa1 = { 6c ce [2] 48 c0 [2] 63 ec [2] 4d ce [2] 59 d5 [2] 56 cf [2] 48 d2 [2] 4a d3 [2] 51 d5 [2] 4d d2 [2] 51 fd }

  condition:
    any of them
}