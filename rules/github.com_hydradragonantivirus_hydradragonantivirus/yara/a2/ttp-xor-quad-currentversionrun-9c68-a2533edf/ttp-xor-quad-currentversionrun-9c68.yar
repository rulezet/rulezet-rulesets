rule TTP_XOR_QUAD_CurrentVersionRun_9c68 {
  strings:
    $key_9c68 = { cf 07 [2] eb 09 [2] c0 25 [2] ee 07 [2] fa 1c [2] f5 06 [2] eb 1b [2] e9 1a [2] f2 1c [2] ee 1b [2] f2 34 }

  condition:
    any of them
}