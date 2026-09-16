rule TTP_XOR_QUAD_CurrentVersionRun_96aa {
  strings:
    $key_96aa = { c5 c5 [2] e1 cb [2] ca e7 [2] e4 c5 [2] f0 de [2] ff c4 [2] e1 d9 [2] e3 d8 [2] f8 de [2] e4 d9 [2] f8 f6 }

  condition:
    any of them
}