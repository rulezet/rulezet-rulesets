rule TTP_XOR_QUAD_CurrentVersionRun_9c27 {
  strings:
    $key_9c27 = { cf 48 [2] eb 46 [2] c0 6a [2] ee 48 [2] fa 53 [2] f5 49 [2] eb 54 [2] e9 55 [2] f2 53 [2] ee 54 [2] f2 7b }

  condition:
    any of them
}