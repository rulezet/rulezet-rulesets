rule TTP_XOR_QUAD_CurrentVersionRun_9c3e {
  strings:
    $key_9c3e = { cf 51 [2] eb 5f [2] c0 73 [2] ee 51 [2] fa 4a [2] f5 50 [2] eb 4d [2] e9 4c [2] f2 4a [2] ee 4d [2] f2 62 }

  condition:
    any of them
}