rule TTP_XOR_QUAD_CurrentVersionRun_81b6 {
  strings:
    $key_81b6 = { d2 d9 [2] f6 d7 [2] dd fb [2] f3 d9 [2] e7 c2 [2] e8 d8 [2] f6 c5 [2] f4 c4 [2] ef c2 [2] f3 c5 [2] ef ea }

  condition:
    any of them
}