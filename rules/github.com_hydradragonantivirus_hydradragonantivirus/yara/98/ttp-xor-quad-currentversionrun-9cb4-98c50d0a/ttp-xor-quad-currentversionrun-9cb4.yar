rule TTP_XOR_QUAD_CurrentVersionRun_9cb4 {
  strings:
    $key_9cb4 = { cf db [2] eb d5 [2] c0 f9 [2] ee db [2] fa c0 [2] f5 da [2] eb c7 [2] e9 c6 [2] f2 c0 [2] ee c7 [2] f2 e8 }

  condition:
    any of them
}