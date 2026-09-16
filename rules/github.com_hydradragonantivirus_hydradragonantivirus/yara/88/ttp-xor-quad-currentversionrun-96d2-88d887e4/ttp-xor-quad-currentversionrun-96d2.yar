rule TTP_XOR_QUAD_CurrentVersionRun_96d2 {
  strings:
    $key_96d2 = { c5 bd [2] e1 b3 [2] ca 9f [2] e4 bd [2] f0 a6 [2] ff bc [2] e1 a1 [2] e3 a0 [2] f8 a6 [2] e4 a1 [2] f8 8e }

  condition:
    any of them
}