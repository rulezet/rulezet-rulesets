rule TTP_XOR_QUAD_CurrentVersionRun_87af {
  strings:
    $key_87af = { d4 c0 [2] f0 ce [2] db e2 [2] f5 c0 [2] e1 db [2] ee c1 [2] f0 dc [2] f2 dd [2] e9 db [2] f5 dc [2] e9 f3 }

  condition:
    any of them
}