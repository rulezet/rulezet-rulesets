rule TTP_XOR_QUAD_CurrentVersionRun_9c1a {
  strings:
    $key_9c1a = { cf 75 [2] eb 7b [2] c0 57 [2] ee 75 [2] fa 6e [2] f5 74 [2] eb 69 [2] e9 68 [2] f2 6e [2] ee 69 [2] f2 46 }

  condition:
    any of them
}