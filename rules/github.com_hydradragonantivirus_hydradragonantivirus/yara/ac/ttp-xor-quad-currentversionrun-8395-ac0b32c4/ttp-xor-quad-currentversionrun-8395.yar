rule TTP_XOR_QUAD_CurrentVersionRun_8395 {
  strings:
    $key_8395 = { d0 fa [2] f4 f4 [2] df d8 [2] f1 fa [2] e5 e1 [2] ea fb [2] f4 e6 [2] f6 e7 [2] ed e1 [2] f1 e6 [2] ed c9 }

  condition:
    any of them
}