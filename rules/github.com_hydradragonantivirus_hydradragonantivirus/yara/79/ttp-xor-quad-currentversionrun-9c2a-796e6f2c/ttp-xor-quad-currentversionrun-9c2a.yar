rule TTP_XOR_QUAD_CurrentVersionRun_9c2a {
  strings:
    $key_9c2a = { cf 45 [2] eb 4b [2] c0 67 [2] ee 45 [2] fa 5e [2] f5 44 [2] eb 59 [2] e9 58 [2] f2 5e [2] ee 59 [2] f2 76 }

  condition:
    any of them
}