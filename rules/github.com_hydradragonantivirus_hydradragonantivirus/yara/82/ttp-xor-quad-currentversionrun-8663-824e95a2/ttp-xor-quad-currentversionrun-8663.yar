rule TTP_XOR_QUAD_CurrentVersionRun_8663 {
  strings:
    $key_8663 = { d5 0c [2] f1 02 [2] da 2e [2] f4 0c [2] e0 17 [2] ef 0d [2] f1 10 [2] f3 11 [2] e8 17 [2] f4 10 [2] e8 3f }

  condition:
    any of them
}