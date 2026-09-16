rule TTP_XOR_QUAD_CurrentVersionRun_9cf8 {
  strings:
    $key_9cf8 = { cf 97 [2] eb 99 [2] c0 b5 [2] ee 97 [2] fa 8c [2] f5 96 [2] eb 8b [2] e9 8a [2] f2 8c [2] ee 8b [2] f2 a4 }

  condition:
    any of them
}