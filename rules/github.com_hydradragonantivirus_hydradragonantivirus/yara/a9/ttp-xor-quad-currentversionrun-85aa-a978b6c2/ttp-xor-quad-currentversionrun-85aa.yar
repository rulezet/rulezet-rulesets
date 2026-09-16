rule TTP_XOR_QUAD_CurrentVersionRun_85aa {
  strings:
    $key_85aa = { d6 c5 [2] f2 cb [2] d9 e7 [2] f7 c5 [2] e3 de [2] ec c4 [2] f2 d9 [2] f0 d8 [2] eb de [2] f7 d9 [2] eb f6 }

  condition:
    any of them
}