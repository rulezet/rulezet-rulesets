rule TTP_XOR_QUAD_CurrentVersionRun_9cc0 {
  strings:
    $key_9cc0 = { cf af [2] eb a1 [2] c0 8d [2] ee af [2] fa b4 [2] f5 ae [2] eb b3 [2] e9 b2 [2] f2 b4 [2] ee b3 [2] f2 9c }

  condition:
    any of them
}