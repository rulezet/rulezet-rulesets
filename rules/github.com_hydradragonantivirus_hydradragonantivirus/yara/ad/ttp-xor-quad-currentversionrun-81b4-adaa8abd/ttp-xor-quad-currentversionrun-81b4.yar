rule TTP_XOR_QUAD_CurrentVersionRun_81b4 {
  strings:
    $key_81b4 = { d2 db [2] f6 d5 [2] dd f9 [2] f3 db [2] e7 c0 [2] e8 da [2] f6 c7 [2] f4 c6 [2] ef c0 [2] f3 c7 [2] ef e8 }

  condition:
    any of them
}