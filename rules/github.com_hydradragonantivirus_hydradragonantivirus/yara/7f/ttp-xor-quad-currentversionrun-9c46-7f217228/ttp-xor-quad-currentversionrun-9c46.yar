rule TTP_XOR_QUAD_CurrentVersionRun_9c46 {
  strings:
    $key_9c46 = { cf 29 [2] eb 27 [2] c0 0b [2] ee 29 [2] fa 32 [2] f5 28 [2] eb 35 [2] e9 34 [2] f2 32 [2] ee 35 [2] f2 1a }

  condition:
    any of them
}