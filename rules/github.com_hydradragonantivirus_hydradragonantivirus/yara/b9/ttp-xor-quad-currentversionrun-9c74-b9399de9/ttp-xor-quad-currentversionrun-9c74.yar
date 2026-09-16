rule TTP_XOR_QUAD_CurrentVersionRun_9c74 {
  strings:
    $key_9c74 = { cf 1b [2] eb 15 [2] c0 39 [2] ee 1b [2] fa 00 [2] f5 1a [2] eb 07 [2] e9 06 [2] f2 00 [2] ee 07 [2] f2 28 }

  condition:
    any of them
}