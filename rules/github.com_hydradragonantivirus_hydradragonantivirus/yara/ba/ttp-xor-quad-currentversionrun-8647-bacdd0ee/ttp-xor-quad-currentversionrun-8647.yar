rule TTP_XOR_QUAD_CurrentVersionRun_8647 {
  strings:
    $key_8647 = { d5 28 [2] f1 26 [2] da 0a [2] f4 28 [2] e0 33 [2] ef 29 [2] f1 34 [2] f3 35 [2] e8 33 [2] f4 34 [2] e8 1b }

  condition:
    any of them
}