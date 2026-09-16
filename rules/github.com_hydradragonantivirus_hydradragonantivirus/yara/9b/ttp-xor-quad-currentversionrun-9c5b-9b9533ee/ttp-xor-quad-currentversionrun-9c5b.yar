rule TTP_XOR_QUAD_CurrentVersionRun_9c5b {
  strings:
    $key_9c5b = { cf 34 [2] eb 3a [2] c0 16 [2] ee 34 [2] fa 2f [2] f5 35 [2] eb 28 [2] e9 29 [2] f2 2f [2] ee 28 [2] f2 07 }

  condition:
    any of them
}