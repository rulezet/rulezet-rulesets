rule TTP_XOR_QUAD_CurrentVersionRun_9cbb {
  strings:
    $key_9cbb = { cf d4 [2] eb da [2] c0 f6 [2] ee d4 [2] fa cf [2] f5 d5 [2] eb c8 [2] e9 c9 [2] f2 cf [2] ee c8 [2] f2 e7 }

  condition:
    any of them
}