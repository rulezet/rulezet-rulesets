rule TTP_XOR_QUAD_CurrentVersionRun_9c13 {
  strings:
    $key_9c13 = { cf 7c [2] eb 72 [2] c0 5e [2] ee 7c [2] fa 67 [2] f5 7d [2] eb 60 [2] e9 61 [2] f2 67 [2] ee 60 [2] f2 4f }

  condition:
    any of them
}