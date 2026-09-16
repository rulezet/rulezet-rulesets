rule TTP_XOR_QUAD_CurrentVersionRun_8678 {
  strings:
    $key_8678 = { d5 17 [2] f1 19 [2] da 35 [2] f4 17 [2] e0 0c [2] ef 16 [2] f1 0b [2] f3 0a [2] e8 0c [2] f4 0b [2] e8 24 }

  condition:
    any of them
}