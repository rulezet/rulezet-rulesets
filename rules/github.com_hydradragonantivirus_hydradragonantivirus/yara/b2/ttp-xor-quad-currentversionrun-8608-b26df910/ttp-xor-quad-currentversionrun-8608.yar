rule TTP_XOR_QUAD_CurrentVersionRun_8608 {
  strings:
    $key_8608 = { d5 67 [2] f1 69 [2] da 45 [2] f4 67 [2] e0 7c [2] ef 66 [2] f1 7b [2] f3 7a [2] e8 7c [2] f4 7b [2] e8 54 }

  condition:
    any of them
}