rule TTP_XOR_QUAD_CurrentVersionRun_9c53 {
  strings:
    $key_9c53 = { cf 3c [2] eb 32 [2] c0 1e [2] ee 3c [2] fa 27 [2] f5 3d [2] eb 20 [2] e9 21 [2] f2 27 [2] ee 20 [2] f2 0f }

  condition:
    any of them
}