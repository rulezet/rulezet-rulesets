rule TTP_XOR_QUAD_CurrentVersionRun_9cc5 {
  strings:
    $key_9cc5 = { cf aa [2] eb a4 [2] c0 88 [2] ee aa [2] fa b1 [2] f5 ab [2] eb b6 [2] e9 b7 [2] f2 b1 [2] ee b6 [2] f2 99 }

  condition:
    any of them
}