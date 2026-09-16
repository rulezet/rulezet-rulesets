rule TTP_XOR_QUAD_CurrentVersionRun_8665 {
  strings:
    $key_8665 = { d5 0a [2] f1 04 [2] da 28 [2] f4 0a [2] e0 11 [2] ef 0b [2] f1 16 [2] f3 17 [2] e8 11 [2] f4 16 [2] e8 39 }

  condition:
    any of them
}