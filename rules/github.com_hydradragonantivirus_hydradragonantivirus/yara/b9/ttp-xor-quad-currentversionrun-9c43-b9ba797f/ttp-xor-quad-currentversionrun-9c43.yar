rule TTP_XOR_QUAD_CurrentVersionRun_9c43 {
  strings:
    $key_9c43 = { cf 2c [2] eb 22 [2] c0 0e [2] ee 2c [2] fa 37 [2] f5 2d [2] eb 30 [2] e9 31 [2] f2 37 [2] ee 30 [2] f2 1f }

  condition:
    any of them
}