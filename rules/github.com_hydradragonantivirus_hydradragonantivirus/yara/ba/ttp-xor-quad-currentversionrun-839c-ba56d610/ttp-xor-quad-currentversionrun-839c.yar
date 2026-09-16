rule TTP_XOR_QUAD_CurrentVersionRun_839c {
  strings:
    $key_839c = { d0 f3 [2] f4 fd [2] df d1 [2] f1 f3 [2] e5 e8 [2] ea f2 [2] f4 ef [2] f6 ee [2] ed e8 [2] f1 ef [2] ed c0 }

  condition:
    any of them
}