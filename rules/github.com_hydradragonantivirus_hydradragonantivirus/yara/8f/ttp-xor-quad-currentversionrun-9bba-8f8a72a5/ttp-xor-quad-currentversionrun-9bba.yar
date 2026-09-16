rule TTP_XOR_QUAD_CurrentVersionRun_9bba {
  strings:
    $key_9bba = { c8 d5 [2] ec db [2] c7 f7 [2] e9 d5 [2] fd ce [2] f2 d4 [2] ec c9 [2] ee c8 [2] f5 ce [2] e9 c9 [2] f5 e6 }

  condition:
    any of them
}