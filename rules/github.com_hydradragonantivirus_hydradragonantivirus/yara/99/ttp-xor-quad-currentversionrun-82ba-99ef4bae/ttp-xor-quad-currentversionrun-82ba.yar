rule TTP_XOR_QUAD_CurrentVersionRun_82ba {
  strings:
    $key_82ba = { d1 d5 [2] f5 db [2] de f7 [2] f0 d5 [2] e4 ce [2] eb d4 [2] f5 c9 [2] f7 c8 [2] ec ce [2] f0 c9 [2] ec e6 }

  condition:
    any of them
}