rule TTP_XOR_QUAD_CurrentVersionRun_9cf5 {
  strings:
    $key_9cf5 = { cf 9a [2] eb 94 [2] c0 b8 [2] ee 9a [2] fa 81 [2] f5 9b [2] eb 86 [2] e9 87 [2] f2 81 [2] ee 86 [2] f2 a9 }

  condition:
    any of them
}