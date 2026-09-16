rule TTP_XOR_QUAD_CurrentVersionRun_8658 {
  strings:
    $key_8658 = { d5 37 [2] f1 39 [2] da 15 [2] f4 37 [2] e0 2c [2] ef 36 [2] f1 2b [2] f3 2a [2] e8 2c [2] f4 2b [2] e8 04 }

  condition:
    any of them
}