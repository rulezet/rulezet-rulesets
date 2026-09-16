rule TTP_XOR_QUAD_CurrentVersionRun_969c {
  strings:
    $key_969c = { c5 f3 [2] e1 fd [2] ca d1 [2] e4 f3 [2] f0 e8 [2] ff f2 [2] e1 ef [2] e3 ee [2] f8 e8 [2] e4 ef [2] f8 c0 }

  condition:
    any of them
}