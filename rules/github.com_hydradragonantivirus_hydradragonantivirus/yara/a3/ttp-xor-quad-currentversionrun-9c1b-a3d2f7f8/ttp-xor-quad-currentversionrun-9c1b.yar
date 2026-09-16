rule TTP_XOR_QUAD_CurrentVersionRun_9c1b {
  strings:
    $key_9c1b = { cf 74 [2] eb 7a [2] c0 56 [2] ee 74 [2] fa 6f [2] f5 75 [2] eb 68 [2] e9 69 [2] f2 6f [2] ee 68 [2] f2 47 }

  condition:
    any of them
}