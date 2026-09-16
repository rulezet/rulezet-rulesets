rule TTP_XOR_QUAD_CurrentVersionRun_9c6e {
  strings:
    $key_9c6e = { cf 01 [2] eb 0f [2] c0 23 [2] ee 01 [2] fa 1a [2] f5 00 [2] eb 1d [2] e9 1c [2] f2 1a [2] ee 1d [2] f2 32 }

  condition:
    any of them
}