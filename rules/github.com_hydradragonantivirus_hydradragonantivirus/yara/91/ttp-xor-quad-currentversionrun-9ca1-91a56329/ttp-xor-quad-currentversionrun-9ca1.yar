rule TTP_XOR_QUAD_CurrentVersionRun_9ca1 {
  strings:
    $key_9ca1 = { cf ce [2] eb c0 [2] c0 ec [2] ee ce [2] fa d5 [2] f5 cf [2] eb d2 [2] e9 d3 [2] f2 d5 [2] ee d2 [2] f2 fd }

  condition:
    any of them
}