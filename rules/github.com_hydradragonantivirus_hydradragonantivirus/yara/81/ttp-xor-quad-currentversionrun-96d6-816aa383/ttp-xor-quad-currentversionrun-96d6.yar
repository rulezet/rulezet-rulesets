rule TTP_XOR_QUAD_CurrentVersionRun_96d6 {
  strings:
    $key_96d6 = { c5 b9 [2] e1 b7 [2] ca 9b [2] e4 b9 [2] f0 a2 [2] ff b8 [2] e1 a5 [2] e3 a4 [2] f8 a2 [2] e4 a5 [2] f8 8a }

  condition:
    any of them
}