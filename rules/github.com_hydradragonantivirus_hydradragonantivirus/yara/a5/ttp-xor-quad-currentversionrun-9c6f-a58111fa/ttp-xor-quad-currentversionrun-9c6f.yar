rule TTP_XOR_QUAD_CurrentVersionRun_9c6f {
  strings:
    $key_9c6f = { cf 00 [2] eb 0e [2] c0 22 [2] ee 00 [2] fa 1b [2] f5 01 [2] eb 1c [2] e9 1d [2] f2 1b [2] ee 1c [2] f2 33 }

  condition:
    any of them
}