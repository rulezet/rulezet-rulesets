rule TTP_XOR_QUAD_CurrentVersionRun_9c3a {
  strings:
    $key_9c3a = { cf 55 [2] eb 5b [2] c0 77 [2] ee 55 [2] fa 4e [2] f5 54 [2] eb 49 [2] e9 48 [2] f2 4e [2] ee 49 [2] f2 66 }

  condition:
    any of them
}