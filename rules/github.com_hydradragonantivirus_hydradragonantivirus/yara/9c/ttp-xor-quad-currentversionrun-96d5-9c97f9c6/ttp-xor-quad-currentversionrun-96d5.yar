rule TTP_XOR_QUAD_CurrentVersionRun_96d5 {
  strings:
    $key_96d5 = { c5 ba [2] e1 b4 [2] ca 98 [2] e4 ba [2] f0 a1 [2] ff bb [2] e1 a6 [2] e3 a7 [2] f8 a1 [2] e4 a6 [2] f8 89 }

  condition:
    any of them
}