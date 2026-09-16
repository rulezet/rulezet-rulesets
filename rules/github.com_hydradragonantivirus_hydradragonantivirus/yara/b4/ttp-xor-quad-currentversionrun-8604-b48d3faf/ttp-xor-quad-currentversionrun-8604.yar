rule TTP_XOR_QUAD_CurrentVersionRun_8604 {
  strings:
    $key_8604 = { d5 6b [2] f1 65 [2] da 49 [2] f4 6b [2] e0 70 [2] ef 6a [2] f1 77 [2] f3 76 [2] e8 70 [2] f4 77 [2] e8 58 }

  condition:
    any of them
}