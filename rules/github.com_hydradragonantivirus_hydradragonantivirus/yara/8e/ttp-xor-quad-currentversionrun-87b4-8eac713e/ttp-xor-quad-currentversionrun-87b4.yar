rule TTP_XOR_QUAD_CurrentVersionRun_87b4 {
  strings:
    $key_87b4 = { d4 db [2] f0 d5 [2] db f9 [2] f5 db [2] e1 c0 [2] ee da [2] f0 c7 [2] f2 c6 [2] e9 c0 [2] f5 c7 [2] e9 e8 }

  condition:
    any of them
}