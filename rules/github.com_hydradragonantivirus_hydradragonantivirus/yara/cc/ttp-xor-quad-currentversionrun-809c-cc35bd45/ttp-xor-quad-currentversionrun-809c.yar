rule TTP_XOR_QUAD_CurrentVersionRun_809c {
  strings:
    $key_809c = { d3 f3 [2] f7 fd [2] dc d1 [2] f2 f3 [2] e6 e8 [2] e9 f2 [2] f7 ef [2] f5 ee [2] ee e8 [2] f2 ef [2] ee c0 }

  condition:
    any of them
}