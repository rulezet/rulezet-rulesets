rule TTP_XOR_QUAD_CurrentVersionRun_865b {
  strings:
    $key_865b = { d5 34 [2] f1 3a [2] da 16 [2] f4 34 [2] e0 2f [2] ef 35 [2] f1 28 [2] f3 29 [2] e8 2f [2] f4 28 [2] e8 07 }

  condition:
    any of them
}