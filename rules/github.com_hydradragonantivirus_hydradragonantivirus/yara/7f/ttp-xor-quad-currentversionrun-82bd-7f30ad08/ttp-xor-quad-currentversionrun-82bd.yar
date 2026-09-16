rule TTP_XOR_QUAD_CurrentVersionRun_82bd {
  strings:
    $key_82bd = { d1 d2 [2] f5 dc [2] de f0 [2] f0 d2 [2] e4 c9 [2] eb d3 [2] f5 ce [2] f7 cf [2] ec c9 [2] f0 ce [2] ec e1 }

  condition:
    any of them
}