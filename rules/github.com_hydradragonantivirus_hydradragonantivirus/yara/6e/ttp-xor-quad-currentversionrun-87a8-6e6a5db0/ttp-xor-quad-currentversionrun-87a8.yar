rule TTP_XOR_QUAD_CurrentVersionRun_87a8 {
  strings:
    $key_87a8 = { d4 c7 [2] f0 c9 [2] db e5 [2] f5 c7 [2] e1 dc [2] ee c6 [2] f0 db [2] f2 da [2] e9 dc [2] f5 db [2] e9 f4 }

  condition:
    any of them
}