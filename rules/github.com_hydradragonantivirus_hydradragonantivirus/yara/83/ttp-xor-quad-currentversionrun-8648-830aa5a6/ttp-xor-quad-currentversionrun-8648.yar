rule TTP_XOR_QUAD_CurrentVersionRun_8648 {
  strings:
    $key_8648 = { d5 27 [2] f1 29 [2] da 05 [2] f4 27 [2] e0 3c [2] ef 26 [2] f1 3b [2] f3 3a [2] e8 3c [2] f4 3b [2] e8 14 }

  condition:
    any of them
}