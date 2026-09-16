rule TTP_XOR_QUAD_CurrentVersionRun_9c40 {
  strings:
    $key_9c40 = { cf 2f [2] eb 21 [2] c0 0d [2] ee 2f [2] fa 34 [2] f5 2e [2] eb 33 [2] e9 32 [2] f2 34 [2] ee 33 [2] f2 1c }

  condition:
    any of them
}