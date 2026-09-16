rule TTP_XOR_QUAD_CurrentVersionRun_8654 {
  strings:
    $key_8654 = { d5 3b [2] f1 35 [2] da 19 [2] f4 3b [2] e0 20 [2] ef 3a [2] f1 27 [2] f3 26 [2] e8 20 [2] f4 27 [2] e8 08 }

  condition:
    any of them
}