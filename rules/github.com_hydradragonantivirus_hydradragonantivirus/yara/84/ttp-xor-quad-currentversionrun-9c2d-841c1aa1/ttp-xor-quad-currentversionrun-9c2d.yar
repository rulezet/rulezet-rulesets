rule TTP_XOR_QUAD_CurrentVersionRun_9c2d {
  strings:
    $key_9c2d = { cf 42 [2] eb 4c [2] c0 60 [2] ee 42 [2] fa 59 [2] f5 43 [2] eb 5e [2] e9 5f [2] f2 59 [2] ee 5e [2] f2 71 }

  condition:
    any of them
}