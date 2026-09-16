rule TTP_XOR_QUAD_CurrentVersionRun_9cb5 {
  strings:
    $key_9cb5 = { cf da [2] eb d4 [2] c0 f8 [2] ee da [2] fa c1 [2] f5 db [2] eb c6 [2] e9 c7 [2] f2 c1 [2] ee c6 [2] f2 e9 }

  condition:
    any of them
}