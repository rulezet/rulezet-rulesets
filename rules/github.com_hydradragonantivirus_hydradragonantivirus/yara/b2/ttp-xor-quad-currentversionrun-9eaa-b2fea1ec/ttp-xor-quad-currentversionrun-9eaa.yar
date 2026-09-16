rule TTP_XOR_QUAD_CurrentVersionRun_9eaa {
  strings:
    $key_9eaa = { cd c5 [2] e9 cb [2] c2 e7 [2] ec c5 [2] f8 de [2] f7 c4 [2] e9 d9 [2] eb d8 [2] f0 de [2] ec d9 [2] f0 f6 }

  condition:
    any of them
}