rule TTP_XOR_QUAD_CurrentVersionRun_8605 {
  strings:
    $key_8605 = { d5 6a [2] f1 64 [2] da 48 [2] f4 6a [2] e0 71 [2] ef 6b [2] f1 76 [2] f3 77 [2] e8 71 [2] f4 76 [2] e8 59 }

  condition:
    any of them
}