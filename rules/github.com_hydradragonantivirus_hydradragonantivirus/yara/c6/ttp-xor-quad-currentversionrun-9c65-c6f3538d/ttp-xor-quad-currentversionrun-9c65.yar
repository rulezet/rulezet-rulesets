rule TTP_XOR_QUAD_CurrentVersionRun_9c65 {
  strings:
    $key_9c65 = { cf 0a [2] eb 04 [2] c0 28 [2] ee 0a [2] fa 11 [2] f5 0b [2] eb 16 [2] e9 17 [2] f2 11 [2] ee 16 [2] f2 39 }

  condition:
    any of them
}