rule TTP_XOR_QUAD_CurrentVersionRun_96d7 {
  strings:
    $key_96d7 = { c5 b8 [2] e1 b6 [2] ca 9a [2] e4 b8 [2] f0 a3 [2] ff b9 [2] e1 a4 [2] e3 a5 [2] f8 a3 [2] e4 a4 [2] f8 8b }

  condition:
    any of them
}