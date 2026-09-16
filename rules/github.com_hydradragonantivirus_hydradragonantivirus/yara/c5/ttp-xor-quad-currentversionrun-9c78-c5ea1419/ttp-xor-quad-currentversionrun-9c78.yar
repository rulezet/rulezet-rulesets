rule TTP_XOR_QUAD_CurrentVersionRun_9c78 {
  strings:
    $key_9c78 = { cf 17 [2] eb 19 [2] c0 35 [2] ee 17 [2] fa 0c [2] f5 16 [2] eb 0b [2] e9 0a [2] f2 0c [2] ee 0b [2] f2 24 }

  condition:
    any of them
}