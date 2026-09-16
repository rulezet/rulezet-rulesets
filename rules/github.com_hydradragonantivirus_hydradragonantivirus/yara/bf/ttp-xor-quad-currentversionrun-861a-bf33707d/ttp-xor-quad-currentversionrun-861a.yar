rule TTP_XOR_QUAD_CurrentVersionRun_861a {
  strings:
    $key_861a = { d5 75 [2] f1 7b [2] da 57 [2] f4 75 [2] e0 6e [2] ef 74 [2] f1 69 [2] f3 68 [2] e8 6e [2] f4 69 [2] e8 46 }

  condition:
    any of them
}