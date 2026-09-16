rule TTP_XOR_QUAD_CurrentVersionRun_9c5c {
  strings:
    $key_9c5c = { cf 33 [2] eb 3d [2] c0 11 [2] ee 33 [2] fa 28 [2] f5 32 [2] eb 2f [2] e9 2e [2] f2 28 [2] ee 2f [2] f2 00 }

  condition:
    any of them
}