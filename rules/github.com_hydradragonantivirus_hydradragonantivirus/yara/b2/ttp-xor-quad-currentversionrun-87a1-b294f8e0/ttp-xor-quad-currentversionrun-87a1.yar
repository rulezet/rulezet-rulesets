rule TTP_XOR_QUAD_CurrentVersionRun_87a1 {
  strings:
    $key_87a1 = { d4 ce [2] f0 c0 [2] db ec [2] f5 ce [2] e1 d5 [2] ee cf [2] f0 d2 [2] f2 d3 [2] e9 d5 [2] f5 d2 [2] e9 fd }

  condition:
    any of them
}