rule TTP_XOR_QUAD_CurrentVersionRun_949c {
  strings:
    $key_949c = { c7 f3 [2] e3 fd [2] c8 d1 [2] e6 f3 [2] f2 e8 [2] fd f2 [2] e3 ef [2] e1 ee [2] fa e8 [2] e6 ef [2] fa c0 }

  condition:
    any of them
}