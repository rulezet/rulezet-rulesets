rule TTP_XOR_QUAD_CurrentVersionRun_9c04 {
  strings:
    $key_9c04 = { cf 6b [2] eb 65 [2] c0 49 [2] ee 6b [2] fa 70 [2] f5 6a [2] eb 77 [2] e9 76 [2] f2 70 [2] ee 77 [2] f2 58 }

  condition:
    any of them
}