rule TTP_XOR_QUAD_CurrentVersionRun_9c67 {
  strings:
    $key_9c67 = { cf 08 [2] eb 06 [2] c0 2a [2] ee 08 [2] fa 13 [2] f5 09 [2] eb 14 [2] e9 15 [2] f2 13 [2] ee 14 [2] f2 3b }

  condition:
    any of them
}