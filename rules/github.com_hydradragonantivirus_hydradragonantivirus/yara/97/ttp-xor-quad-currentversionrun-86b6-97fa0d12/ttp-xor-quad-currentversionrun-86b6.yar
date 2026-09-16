rule TTP_XOR_QUAD_CurrentVersionRun_86b6 {
  strings:
    $key_86b6 = { d5 d9 [2] f1 d7 [2] da fb [2] f4 d9 [2] e0 c2 [2] ef d8 [2] f1 c5 [2] f3 c4 [2] e8 c2 [2] f4 c5 [2] e8 ea }

  condition:
    any of them
}