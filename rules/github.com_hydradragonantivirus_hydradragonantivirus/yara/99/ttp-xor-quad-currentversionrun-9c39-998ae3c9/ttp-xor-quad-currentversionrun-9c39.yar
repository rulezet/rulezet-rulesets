rule TTP_XOR_QUAD_CurrentVersionRun_9c39 {
  strings:
    $key_9c39 = { cf 56 [2] eb 58 [2] c0 74 [2] ee 56 [2] fa 4d [2] f5 57 [2] eb 4a [2] e9 4b [2] f2 4d [2] ee 4a [2] f2 65 }

  condition:
    any of them
}