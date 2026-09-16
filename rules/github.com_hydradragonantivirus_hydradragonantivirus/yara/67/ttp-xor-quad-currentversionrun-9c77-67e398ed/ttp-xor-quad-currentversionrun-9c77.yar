rule TTP_XOR_QUAD_CurrentVersionRun_9c77 {
  strings:
    $key_9c77 = { cf 18 [2] eb 16 [2] c0 3a [2] ee 18 [2] fa 03 [2] f5 19 [2] eb 04 [2] e9 05 [2] f2 03 [2] ee 04 [2] f2 2b }

  condition:
    any of them
}