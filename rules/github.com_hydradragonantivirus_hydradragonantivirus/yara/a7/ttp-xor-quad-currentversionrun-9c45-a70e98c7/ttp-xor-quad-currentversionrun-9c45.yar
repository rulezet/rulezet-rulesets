rule TTP_XOR_QUAD_CurrentVersionRun_9c45 {
  strings:
    $key_9c45 = { cf 2a [2] eb 24 [2] c0 08 [2] ee 2a [2] fa 31 [2] f5 2b [2] eb 36 [2] e9 37 [2] f2 31 [2] ee 36 [2] f2 19 }

  condition:
    any of them
}