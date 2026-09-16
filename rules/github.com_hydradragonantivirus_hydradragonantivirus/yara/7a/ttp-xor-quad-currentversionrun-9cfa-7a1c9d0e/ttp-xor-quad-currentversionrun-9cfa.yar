rule TTP_XOR_QUAD_CurrentVersionRun_9cfa {
  strings:
    $key_9cfa = { cf 95 [2] eb 9b [2] c0 b7 [2] ee 95 [2] fa 8e [2] f5 94 [2] eb 89 [2] e9 88 [2] f2 8e [2] ee 89 [2] f2 a6 }

  condition:
    any of them
}