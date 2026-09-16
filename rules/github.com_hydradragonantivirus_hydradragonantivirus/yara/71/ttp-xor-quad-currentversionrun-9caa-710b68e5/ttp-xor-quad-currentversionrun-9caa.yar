rule TTP_XOR_QUAD_CurrentVersionRun_9caa {
  strings:
    $key_9caa = { cf c5 [2] eb cb [2] c0 e7 [2] ee c5 [2] fa de [2] f5 c4 [2] eb d9 [2] e9 d8 [2] f2 de [2] ee d9 [2] f2 f6 }

  condition:
    any of them
}