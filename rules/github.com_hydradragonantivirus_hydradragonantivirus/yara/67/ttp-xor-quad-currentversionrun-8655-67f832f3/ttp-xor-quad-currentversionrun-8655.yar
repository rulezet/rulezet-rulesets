rule TTP_XOR_QUAD_CurrentVersionRun_8655 {
  strings:
    $key_8655 = { d5 3a [2] f1 34 [2] da 18 [2] f4 3a [2] e0 21 [2] ef 3b [2] f1 26 [2] f3 27 [2] e8 21 [2] f4 26 [2] e8 09 }

  condition:
    any of them
}