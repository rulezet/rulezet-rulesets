rule TTP_XOR_QUAD_CurrentVersionRun_9c25 {
  strings:
    $key_9c25 = { cf 4a [2] eb 44 [2] c0 68 [2] ee 4a [2] fa 51 [2] f5 4b [2] eb 56 [2] e9 57 [2] f2 51 [2] ee 56 [2] f2 79 }

  condition:
    any of them
}