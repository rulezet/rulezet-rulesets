rule TTP_XOR_QUAD_CurrentVersionRun_9eba {
  strings:
    $key_9eba = { cd d5 [2] e9 db [2] c2 f7 [2] ec d5 [2] f8 ce [2] f7 d4 [2] e9 c9 [2] eb c8 [2] f0 ce [2] ec c9 [2] f0 e6 }

  condition:
    any of them
}