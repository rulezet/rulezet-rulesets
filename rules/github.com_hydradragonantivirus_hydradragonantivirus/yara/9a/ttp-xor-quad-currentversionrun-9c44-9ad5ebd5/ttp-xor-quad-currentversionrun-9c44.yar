rule TTP_XOR_QUAD_CurrentVersionRun_9c44 {
  strings:
    $key_9c44 = { cf 2b [2] eb 25 [2] c0 09 [2] ee 2b [2] fa 30 [2] f5 2a [2] eb 37 [2] e9 36 [2] f2 30 [2] ee 37 [2] f2 18 }

  condition:
    any of them
}