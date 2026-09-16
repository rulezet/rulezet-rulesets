rule TTP_XOR_QUAD_CurrentVersionRun_86bf {
  strings:
    $key_86bf = { d5 d0 [2] f1 de [2] da f2 [2] f4 d0 [2] e0 cb [2] ef d1 [2] f1 cc [2] f3 cd [2] e8 cb [2] f4 cc [2] e8 e3 }

  condition:
    any of them
}