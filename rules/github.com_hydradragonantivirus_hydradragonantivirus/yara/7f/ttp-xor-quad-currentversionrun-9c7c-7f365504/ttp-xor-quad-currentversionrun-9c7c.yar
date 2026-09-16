rule TTP_XOR_QUAD_CurrentVersionRun_9c7c {
  strings:
    $key_9c7c = { cf 13 [2] eb 1d [2] c0 31 [2] ee 13 [2] fa 08 [2] f5 12 [2] eb 0f [2] e9 0e [2] f2 08 [2] ee 0f [2] f2 20 }

  condition:
    any of them
}