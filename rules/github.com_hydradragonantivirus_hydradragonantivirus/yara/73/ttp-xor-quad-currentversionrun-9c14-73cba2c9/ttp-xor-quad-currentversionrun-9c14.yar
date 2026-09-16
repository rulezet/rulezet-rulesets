rule TTP_XOR_QUAD_CurrentVersionRun_9c14 {
  strings:
    $key_9c14 = { cf 7b [2] eb 75 [2] c0 59 [2] ee 7b [2] fa 60 [2] f5 7a [2] eb 67 [2] e9 66 [2] f2 60 [2] ee 67 [2] f2 48 }

  condition:
    any of them
}