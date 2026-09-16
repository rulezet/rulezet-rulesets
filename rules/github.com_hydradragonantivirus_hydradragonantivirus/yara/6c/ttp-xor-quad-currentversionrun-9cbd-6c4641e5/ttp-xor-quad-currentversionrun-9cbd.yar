rule TTP_XOR_QUAD_CurrentVersionRun_9cbd {
  strings:
    $key_9cbd = { cf d2 [2] eb dc [2] c0 f0 [2] ee d2 [2] fa c9 [2] f5 d3 [2] eb ce [2] e9 cf [2] f2 c9 [2] ee ce [2] f2 e1 }

  condition:
    any of them
}