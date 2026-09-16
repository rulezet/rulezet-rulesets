rule TTP_XOR_QUAD_CurrentVersionRun_9c23 {
  strings:
    $key_9c23 = { cf 4c [2] eb 42 [2] c0 6e [2] ee 4c [2] fa 57 [2] f5 4d [2] eb 50 [2] e9 51 [2] f2 57 [2] ee 50 [2] f2 7f }

  condition:
    any of them
}