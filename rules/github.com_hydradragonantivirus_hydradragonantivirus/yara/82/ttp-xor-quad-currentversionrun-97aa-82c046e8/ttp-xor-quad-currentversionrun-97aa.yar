rule TTP_XOR_QUAD_CurrentVersionRun_97aa {
  strings:
    $key_97aa = { c4 c5 [2] e0 cb [2] cb e7 [2] e5 c5 [2] f1 de [2] fe c4 [2] e0 d9 [2] e2 d8 [2] f9 de [2] e5 d9 [2] f9 f6 }

  condition:
    any of them
}