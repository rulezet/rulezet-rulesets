rule TTP_XOR_QUAD_CurrentVersionRun_87ba {
  strings:
    $key_87ba = { d4 d5 [2] f0 db [2] db f7 [2] f5 d5 [2] e1 ce [2] ee d4 [2] f0 c9 [2] f2 c8 [2] e9 ce [2] f5 c9 [2] e9 e6 }

  condition:
    any of them
}