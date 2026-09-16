rule TTP_XOR_QUAD_CurrentVersionRun_8627 {
  strings:
    $key_8627 = { d5 48 [2] f1 46 [2] da 6a [2] f4 48 [2] e0 53 [2] ef 49 [2] f1 54 [2] f3 55 [2] e8 53 [2] f4 54 [2] e8 7b }

  condition:
    any of them
}