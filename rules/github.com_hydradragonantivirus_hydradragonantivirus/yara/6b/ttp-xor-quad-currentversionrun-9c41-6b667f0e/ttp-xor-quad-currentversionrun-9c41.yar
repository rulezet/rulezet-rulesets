rule TTP_XOR_QUAD_CurrentVersionRun_9c41 {
  strings:
    $key_9c41 = { cf 2e [2] eb 20 [2] c0 0c [2] ee 2e [2] fa 35 [2] f5 2f [2] eb 32 [2] e9 33 [2] f2 35 [2] ee 32 [2] f2 1d }

  condition:
    any of them
}