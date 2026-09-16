rule TTP_XOR_QUAD_CurrentVersionRun_9c26 {
  strings:
    $key_9c26 = { cf 49 [2] eb 47 [2] c0 6b [2] ee 49 [2] fa 52 [2] f5 48 [2] eb 55 [2] e9 54 [2] f2 52 [2] ee 55 [2] f2 7a }

  condition:
    any of them
}