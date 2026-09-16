rule TTP_XOR_QUAD_CurrentVersionRun_9c72 {
  strings:
    $key_9c72 = { cf 1d [2] eb 13 [2] c0 3f [2] ee 1d [2] fa 06 [2] f5 1c [2] eb 01 [2] e9 00 [2] f2 06 [2] ee 01 [2] f2 2e }

  condition:
    any of them
}