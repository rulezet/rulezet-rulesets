rule TTP_XOR_QUAD_CurrentVersionRun_8640 {
  strings:
    $key_8640 = { d5 2f [2] f1 21 [2] da 0d [2] f4 2f [2] e0 34 [2] ef 2e [2] f1 33 [2] f3 32 [2] e8 34 [2] f4 33 [2] e8 1c }

  condition:
    any of them
}