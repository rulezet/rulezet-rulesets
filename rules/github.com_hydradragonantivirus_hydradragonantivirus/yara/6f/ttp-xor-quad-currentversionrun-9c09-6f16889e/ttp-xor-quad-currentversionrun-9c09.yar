rule TTP_XOR_QUAD_CurrentVersionRun_9c09 {
  strings:
    $key_9c09 = { cf 66 [2] eb 68 [2] c0 44 [2] ee 66 [2] fa 7d [2] f5 67 [2] eb 7a [2] e9 7b [2] f2 7d [2] ee 7a [2] f2 55 }

  condition:
    any of them
}