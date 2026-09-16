rule TTP_XOR_QUAD_CurrentVersionRun_9c59 {
  strings:
    $key_9c59 = { cf 36 [2] eb 38 [2] c0 14 [2] ee 36 [2] fa 2d [2] f5 37 [2] eb 2a [2] e9 2b [2] f2 2d [2] ee 2a [2] f2 05 }

  condition:
    any of them
}