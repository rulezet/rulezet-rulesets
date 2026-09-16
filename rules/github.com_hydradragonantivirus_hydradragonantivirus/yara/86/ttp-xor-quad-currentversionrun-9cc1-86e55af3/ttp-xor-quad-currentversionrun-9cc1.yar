rule TTP_XOR_QUAD_CurrentVersionRun_9cc1 {
  strings:
    $key_9cc1 = { cf ae [2] eb a0 [2] c0 8c [2] ee ae [2] fa b5 [2] f5 af [2] eb b2 [2] e9 b3 [2] f2 b5 [2] ee b2 [2] f2 9d }

  condition:
    any of them
}