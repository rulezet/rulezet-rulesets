rule TTP_XOR_QUAD_CurrentVersionRun_9c16 {
  strings:
    $key_9c16 = { cf 79 [2] eb 77 [2] c0 5b [2] ee 79 [2] fa 62 [2] f5 78 [2] eb 65 [2] e9 64 [2] f2 62 [2] ee 65 [2] f2 4a }

  condition:
    any of them
}