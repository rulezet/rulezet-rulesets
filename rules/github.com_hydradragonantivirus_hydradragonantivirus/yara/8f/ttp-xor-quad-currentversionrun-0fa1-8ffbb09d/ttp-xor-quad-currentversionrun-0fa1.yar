rule TTP_XOR_QUAD_CurrentVersionRun_0fa1 {
  strings:
    $key_0fa1 = { 5c ce [2] 78 c0 [2] 53 ec [2] 7d ce [2] 69 d5 [2] 66 cf [2] 78 d2 [2] 7a d3 [2] 61 d5 [2] 7d d2 [2] 61 fd }

  condition:
    any of them
}