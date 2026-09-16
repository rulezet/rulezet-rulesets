rule TTP_XOR_QUAD_CurrentVersionRun_9c42 {
  strings:
    $key_9c42 = { cf 2d [2] eb 23 [2] c0 0f [2] ee 2d [2] fa 36 [2] f5 2c [2] eb 31 [2] e9 30 [2] f2 36 [2] ee 31 [2] f2 1e }

  condition:
    any of them
}