rule TTP_XOR_QUAD_CurrentVersionRun_9c2e {
  strings:
    $key_9c2e = { cf 41 [2] eb 4f [2] c0 63 [2] ee 41 [2] fa 5a [2] f5 40 [2] eb 5d [2] e9 5c [2] f2 5a [2] ee 5d [2] f2 72 }

  condition:
    any of them
}