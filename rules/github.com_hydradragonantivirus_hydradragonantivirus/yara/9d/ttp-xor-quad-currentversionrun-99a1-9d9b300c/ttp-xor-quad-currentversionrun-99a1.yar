rule TTP_XOR_QUAD_CurrentVersionRun_99a1 {
  strings:
    $key_99a1 = { ca ce [2] ee c0 [2] c5 ec [2] eb ce [2] ff d5 [2] f0 cf [2] ee d2 [2] ec d3 [2] f7 d5 [2] eb d2 [2] f7 fd }

  condition:
    any of them
}