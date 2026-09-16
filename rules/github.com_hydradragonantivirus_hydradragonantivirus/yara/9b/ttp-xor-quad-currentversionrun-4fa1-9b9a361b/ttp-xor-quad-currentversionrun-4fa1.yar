rule TTP_XOR_QUAD_CurrentVersionRun_4fa1 {
  strings:
    $key_4fa1 = { 1c ce [2] 38 c0 [2] 13 ec [2] 3d ce [2] 29 d5 [2] 26 cf [2] 38 d2 [2] 3a d3 [2] 21 d5 [2] 3d d2 [2] 21 fd }

  condition:
    any of them
}