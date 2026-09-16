rule TTP_XOR_QUAD_CurrentVersionRun_869c {
  strings:
    $key_869c = { d5 f3 [2] f1 fd [2] da d1 [2] f4 f3 [2] e0 e8 [2] ef f2 [2] f1 ef [2] f3 ee [2] e8 e8 [2] f4 ef [2] e8 c0 }

  condition:
    any of them
}