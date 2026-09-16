rule TTP_XOR_QUAD_CurrentVersionRun_9c37 {
  strings:
    $key_9c37 = { cf 58 [2] eb 56 [2] c0 7a [2] ee 58 [2] fa 43 [2] f5 59 [2] eb 44 [2] e9 45 [2] f2 43 [2] ee 44 [2] f2 6b }

  condition:
    any of them
}