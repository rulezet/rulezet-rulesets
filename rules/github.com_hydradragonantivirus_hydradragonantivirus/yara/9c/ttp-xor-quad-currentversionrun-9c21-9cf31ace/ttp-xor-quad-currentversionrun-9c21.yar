rule TTP_XOR_QUAD_CurrentVersionRun_9c21 {
  strings:
    $key_9c21 = { cf 4e [2] eb 40 [2] c0 6c [2] ee 4e [2] fa 55 [2] f5 4f [2] eb 52 [2] e9 53 [2] f2 55 [2] ee 52 [2] f2 7d }

  condition:
    any of them
}