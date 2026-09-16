rule TTP_XOR_QUAD_CurrentVersionRun_96b5 {
  strings:
    $key_96b5 = { c5 da [2] e1 d4 [2] ca f8 [2] e4 da [2] f0 c1 [2] ff db [2] e1 c6 [2] e3 c7 [2] f8 c1 [2] e4 c6 [2] f8 e9 }

  condition:
    any of them
}