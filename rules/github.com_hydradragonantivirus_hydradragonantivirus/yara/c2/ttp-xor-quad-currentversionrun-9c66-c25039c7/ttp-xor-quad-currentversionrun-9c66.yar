rule TTP_XOR_QUAD_CurrentVersionRun_9c66 {
  strings:
    $key_9c66 = { cf 09 [2] eb 07 [2] c0 2b [2] ee 09 [2] fa 12 [2] f5 08 [2] eb 15 [2] e9 14 [2] f2 12 [2] ee 15 [2] f2 3a }

  condition:
    any of them
}