rule TTP_XOR_QUAD_CurrentVersionRun_9cf1 {
  strings:
    $key_9cf1 = { cf 9e [2] eb 90 [2] c0 bc [2] ee 9e [2] fa 85 [2] f5 9f [2] eb 82 [2] e9 83 [2] f2 85 [2] ee 82 [2] f2 ad }

  condition:
    any of them
}