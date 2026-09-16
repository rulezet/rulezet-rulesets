rule TTP_XOR_QUAD_CurrentVersionRun_8659 {
  strings:
    $key_8659 = { d5 36 [2] f1 38 [2] da 14 [2] f4 36 [2] e0 2d [2] ef 37 [2] f1 2a [2] f3 2b [2] e8 2d [2] f4 2a [2] e8 05 }

  condition:
    any of them
}