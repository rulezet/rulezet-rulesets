rule TTP_XOR_QUAD_CurrentVersionRun_9c12 {
  strings:
    $key_9c12 = { cf 7d [2] eb 73 [2] c0 5f [2] ee 7d [2] fa 66 [2] f5 7c [2] eb 61 [2] e9 60 [2] f2 66 [2] ee 61 [2] f2 4e }

  condition:
    any of them
}