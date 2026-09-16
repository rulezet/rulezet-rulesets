rule TTP_XOR_QUAD_CurrentVersionRun_9c5d {
  strings:
    $key_9c5d = { cf 32 [2] eb 3c [2] c0 10 [2] ee 32 [2] fa 29 [2] f5 33 [2] eb 2e [2] e9 2f [2] f2 29 [2] ee 2e [2] f2 01 }

  condition:
    any of them
}