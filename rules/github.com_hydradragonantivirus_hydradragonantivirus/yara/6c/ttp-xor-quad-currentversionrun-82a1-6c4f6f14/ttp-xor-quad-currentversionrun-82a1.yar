rule TTP_XOR_QUAD_CurrentVersionRun_82a1 {
  strings:
    $key_82a1 = { d1 ce [2] f5 c0 [2] de ec [2] f0 ce [2] e4 d5 [2] eb cf [2] f5 d2 [2] f7 d3 [2] ec d5 [2] f0 d2 [2] ec fd }

  condition:
    any of them
}