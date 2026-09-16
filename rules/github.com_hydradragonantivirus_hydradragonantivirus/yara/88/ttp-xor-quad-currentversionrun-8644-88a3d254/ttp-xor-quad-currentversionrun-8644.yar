rule TTP_XOR_QUAD_CurrentVersionRun_8644 {
  strings:
    $key_8644 = { d5 2b [2] f1 25 [2] da 09 [2] f4 2b [2] e0 30 [2] ef 2a [2] f1 37 [2] f3 36 [2] e8 30 [2] f4 37 [2] e8 18 }

  condition:
    any of them
}