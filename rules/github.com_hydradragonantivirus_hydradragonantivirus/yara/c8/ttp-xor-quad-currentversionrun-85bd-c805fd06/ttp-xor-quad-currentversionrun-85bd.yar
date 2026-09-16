rule TTP_XOR_QUAD_CurrentVersionRun_85bd {
  strings:
    $key_85bd = { d6 d2 [2] f2 dc [2] d9 f0 [2] f7 d2 [2] e3 c9 [2] ec d3 [2] f2 ce [2] f0 cf [2] eb c9 [2] f7 ce [2] eb e1 }

  condition:
    any of them
}