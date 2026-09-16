rule TTP_XOR_QUAD_CurrentVersionRun_9c56 {
  strings:
    $key_9c56 = { cf 39 [2] eb 37 [2] c0 1b [2] ee 39 [2] fa 22 [2] f5 38 [2] eb 25 [2] e9 24 [2] f2 22 [2] ee 25 [2] f2 0a }

  condition:
    any of them
}