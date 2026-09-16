rule TTP_XOR_QUAD_CurrentVersionRun_9c15 {
  strings:
    $key_9c15 = { cf 7a [2] eb 74 [2] c0 58 [2] ee 7a [2] fa 61 [2] f5 7b [2] eb 66 [2] e9 67 [2] f2 61 [2] ee 66 [2] f2 49 }

  condition:
    any of them
}