rule TTP_XOR_QUAD_CurrentVersionRun_82aa {
  strings:
    $key_82aa = { d1 c5 [2] f5 cb [2] de e7 [2] f0 c5 [2] e4 de [2] eb c4 [2] f5 d9 [2] f7 d8 [2] ec de [2] f0 d9 [2] ec f6 }

  condition:
    any of them
}