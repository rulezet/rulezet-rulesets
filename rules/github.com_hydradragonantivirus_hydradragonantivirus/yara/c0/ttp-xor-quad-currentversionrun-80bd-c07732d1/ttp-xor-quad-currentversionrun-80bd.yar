rule TTP_XOR_QUAD_CurrentVersionRun_80bd {
  strings:
    $key_80bd = { d3 d2 [2] f7 dc [2] dc f0 [2] f2 d2 [2] e6 c9 [2] e9 d3 [2] f7 ce [2] f5 cf [2] ee c9 [2] f2 ce [2] ee e1 }

  condition:
    any of them
}