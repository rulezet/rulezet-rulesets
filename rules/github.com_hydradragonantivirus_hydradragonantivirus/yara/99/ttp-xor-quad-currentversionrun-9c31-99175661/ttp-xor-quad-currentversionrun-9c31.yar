rule TTP_XOR_QUAD_CurrentVersionRun_9c31 {
  strings:
    $key_9c31 = { cf 5e [2] eb 50 [2] c0 7c [2] ee 5e [2] fa 45 [2] f5 5f [2] eb 42 [2] e9 43 [2] f2 45 [2] ee 42 [2] f2 6d }

  condition:
    any of them
}