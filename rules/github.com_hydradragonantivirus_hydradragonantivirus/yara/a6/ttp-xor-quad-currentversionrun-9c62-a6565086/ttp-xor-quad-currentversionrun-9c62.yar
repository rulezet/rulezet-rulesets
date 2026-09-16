rule TTP_XOR_QUAD_CurrentVersionRun_9c62 {
  strings:
    $key_9c62 = { cf 0d [2] eb 03 [2] c0 2f [2] ee 0d [2] fa 16 [2] f5 0c [2] eb 11 [2] e9 10 [2] f2 16 [2] ee 11 [2] f2 3e }

  condition:
    any of them
}