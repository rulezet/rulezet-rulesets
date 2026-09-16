rule TTP_XOR_QUAD_CurrentVersionRun_87aa {
  strings:
    $key_87aa = { d4 c5 [2] f0 cb [2] db e7 [2] f5 c5 [2] e1 de [2] ee c4 [2] f0 d9 [2] f2 d8 [2] e9 de [2] f5 d9 [2] e9 f6 }

  condition:
    any of them
}