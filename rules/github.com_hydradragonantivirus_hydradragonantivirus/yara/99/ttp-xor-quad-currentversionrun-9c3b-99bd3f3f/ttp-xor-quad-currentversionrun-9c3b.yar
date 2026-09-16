rule TTP_XOR_QUAD_CurrentVersionRun_9c3b {
  strings:
    $key_9c3b = { cf 54 [2] eb 5a [2] c0 76 [2] ee 54 [2] fa 4f [2] f5 55 [2] eb 48 [2] e9 49 [2] f2 4f [2] ee 48 [2] f2 67 }

  condition:
    any of them
}