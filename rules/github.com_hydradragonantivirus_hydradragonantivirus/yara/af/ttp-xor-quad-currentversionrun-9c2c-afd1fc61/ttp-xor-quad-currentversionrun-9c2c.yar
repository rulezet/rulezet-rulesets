rule TTP_XOR_QUAD_CurrentVersionRun_9c2c {
  strings:
    $key_9c2c = { cf 43 [2] eb 4d [2] c0 61 [2] ee 43 [2] fa 58 [2] f5 42 [2] eb 5f [2] e9 5e [2] f2 58 [2] ee 5f [2] f2 70 }

  condition:
    any of them
}