rule TTP_XOR_QUAD_CurrentVersionRun_81b5 {
  strings:
    $key_81b5 = { d2 da [2] f6 d4 [2] dd f8 [2] f3 da [2] e7 c1 [2] e8 db [2] f6 c6 [2] f4 c7 [2] ef c1 [2] f3 c6 [2] ef e9 }

  condition:
    any of them
}