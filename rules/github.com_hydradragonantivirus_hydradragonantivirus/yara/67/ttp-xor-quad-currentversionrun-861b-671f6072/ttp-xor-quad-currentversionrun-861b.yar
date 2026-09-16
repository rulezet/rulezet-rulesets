rule TTP_XOR_QUAD_CurrentVersionRun_861b {
  strings:
    $key_861b = { d5 74 [2] f1 7a [2] da 56 [2] f4 74 [2] e0 6f [2] ef 75 [2] f1 68 [2] f3 69 [2] e8 6f [2] f4 68 [2] e8 47 }

  condition:
    any of them
}