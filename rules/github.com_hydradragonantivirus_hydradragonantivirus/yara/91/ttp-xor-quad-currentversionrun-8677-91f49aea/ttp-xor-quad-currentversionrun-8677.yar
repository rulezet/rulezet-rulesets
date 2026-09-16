rule TTP_XOR_QUAD_CurrentVersionRun_8677 {
  strings:
    $key_8677 = { d5 18 [2] f1 16 [2] da 3a [2] f4 18 [2] e0 03 [2] ef 19 [2] f1 04 [2] f3 05 [2] e8 03 [2] f4 04 [2] e8 2b }

  condition:
    any of them
}