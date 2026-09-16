rule TTP_XOR_QUAD_CurrentVersionRun_9ea1 {
  strings:
    $key_9ea1 = { cd ce [2] e9 c0 [2] c2 ec [2] ec ce [2] f8 d5 [2] f7 cf [2] e9 d2 [2] eb d3 [2] f0 d5 [2] ec d2 [2] f0 fd }

  condition:
    any of them
}