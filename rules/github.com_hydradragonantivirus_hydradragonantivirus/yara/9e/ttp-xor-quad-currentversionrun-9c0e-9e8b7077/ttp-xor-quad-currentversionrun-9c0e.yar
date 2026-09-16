rule TTP_XOR_QUAD_CurrentVersionRun_9c0e {
  strings:
    $key_9c0e = { cf 61 [2] eb 6f [2] c0 43 [2] ee 61 [2] fa 7a [2] f5 60 [2] eb 7d [2] e9 7c [2] f2 7a [2] ee 7d [2] f2 52 }

  condition:
    any of them
}