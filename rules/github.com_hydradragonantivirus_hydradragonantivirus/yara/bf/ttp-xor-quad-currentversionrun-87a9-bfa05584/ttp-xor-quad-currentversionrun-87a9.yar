rule TTP_XOR_QUAD_CurrentVersionRun_87a9 {
  strings:
    $key_87a9 = { d4 c6 [2] f0 c8 [2] db e4 [2] f5 c6 [2] e1 dd [2] ee c7 [2] f0 da [2] f2 db [2] e9 dd [2] f5 da [2] e9 f5 }

  condition:
    any of them
}