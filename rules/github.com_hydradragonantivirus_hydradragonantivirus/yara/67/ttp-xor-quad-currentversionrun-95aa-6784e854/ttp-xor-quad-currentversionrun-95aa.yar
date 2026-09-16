rule TTP_XOR_QUAD_CurrentVersionRun_95aa {
  strings:
    $key_95aa = { c6 c5 [2] e2 cb [2] c9 e7 [2] e7 c5 [2] f3 de [2] fc c4 [2] e2 d9 [2] e0 d8 [2] fb de [2] e7 d9 [2] fb f6 }

  condition:
    any of them
}