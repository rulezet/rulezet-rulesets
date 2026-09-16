rule TTP_XOR_QUAD_CurrentVersionRun_9c34 {
  strings:
    $key_9c34 = { cf 5b [2] eb 55 [2] c0 79 [2] ee 5b [2] fa 40 [2] f5 5a [2] eb 47 [2] e9 46 [2] f2 40 [2] ee 47 [2] f2 68 }

  condition:
    any of them
}