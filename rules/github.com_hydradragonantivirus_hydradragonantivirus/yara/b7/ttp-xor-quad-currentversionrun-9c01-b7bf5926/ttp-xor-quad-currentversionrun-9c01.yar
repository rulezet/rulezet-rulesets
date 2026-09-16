rule TTP_XOR_QUAD_CurrentVersionRun_9c01 {
  strings:
    $key_9c01 = { cf 6e [2] eb 60 [2] c0 4c [2] ee 6e [2] fa 75 [2] f5 6f [2] eb 72 [2] e9 73 [2] f2 75 [2] ee 72 [2] f2 5d }

  condition:
    any of them
}