rule TTP_XOR_QUAD_CurrentVersionRun_81b7 {
  strings:
    $key_81b7 = { d2 d8 [2] f6 d6 [2] dd fa [2] f3 d8 [2] e7 c3 [2] e8 d9 [2] f6 c4 [2] f4 c5 [2] ef c3 [2] f3 c4 [2] ef eb }

  condition:
    any of them
}