rule TTP_XOR_QUAD_CurrentVersionRun_9cf4 {
  strings:
    $key_9cf4 = { cf 9b [2] eb 95 [2] c0 b9 [2] ee 9b [2] fa 80 [2] f5 9a [2] eb 87 [2] e9 86 [2] f2 80 [2] ee 87 [2] f2 a8 }

  condition:
    any of them
}