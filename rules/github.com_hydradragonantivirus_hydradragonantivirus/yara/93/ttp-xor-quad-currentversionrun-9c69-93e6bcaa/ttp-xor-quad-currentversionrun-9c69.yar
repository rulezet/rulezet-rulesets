rule TTP_XOR_QUAD_CurrentVersionRun_9c69 {
  strings:
    $key_9c69 = { cf 06 [2] eb 08 [2] c0 24 [2] ee 06 [2] fa 1d [2] f5 07 [2] eb 1a [2] e9 1b [2] f2 1d [2] ee 1a [2] f2 35 }

  condition:
    any of them
}