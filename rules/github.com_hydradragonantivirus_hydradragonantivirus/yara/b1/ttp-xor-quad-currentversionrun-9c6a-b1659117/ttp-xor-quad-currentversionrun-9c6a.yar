rule TTP_XOR_QUAD_CurrentVersionRun_9c6a {
  strings:
    $key_9c6a = { cf 05 [2] eb 0b [2] c0 27 [2] ee 05 [2] fa 1e [2] f5 04 [2] eb 19 [2] e9 18 [2] f2 1e [2] ee 19 [2] f2 36 }

  condition:
    any of them
}