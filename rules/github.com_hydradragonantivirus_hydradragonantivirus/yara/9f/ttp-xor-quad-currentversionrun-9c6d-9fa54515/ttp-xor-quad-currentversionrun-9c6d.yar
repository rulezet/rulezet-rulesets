rule TTP_XOR_QUAD_CurrentVersionRun_9c6d {
  strings:
    $key_9c6d = { cf 02 [2] eb 0c [2] c0 20 [2] ee 02 [2] fa 19 [2] f5 03 [2] eb 1e [2] e9 1f [2] f2 19 [2] ee 1e [2] f2 31 }

  condition:
    any of them
}