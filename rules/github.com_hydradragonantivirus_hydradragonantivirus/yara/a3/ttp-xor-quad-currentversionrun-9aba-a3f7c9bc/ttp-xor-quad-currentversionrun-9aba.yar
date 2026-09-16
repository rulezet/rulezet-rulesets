rule TTP_XOR_QUAD_CurrentVersionRun_9aba {
  strings:
    $key_9aba = { c9 d5 [2] ed db [2] c6 f7 [2] e8 d5 [2] fc ce [2] f3 d4 [2] ed c9 [2] ef c8 [2] f4 ce [2] e8 c9 [2] f4 e6 }

  condition:
    any of them
}