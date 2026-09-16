rule TTP_XOR_QUAD_CurrentVersionRun_8645 {
  strings:
    $key_8645 = { d5 2a [2] f1 24 [2] da 08 [2] f4 2a [2] e0 31 [2] ef 2b [2] f1 36 [2] f3 37 [2] e8 31 [2] f4 36 [2] e8 19 }

  condition:
    any of them
}