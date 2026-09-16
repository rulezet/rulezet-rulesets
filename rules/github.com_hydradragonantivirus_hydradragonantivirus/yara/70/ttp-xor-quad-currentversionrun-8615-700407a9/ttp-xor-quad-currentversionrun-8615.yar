rule TTP_XOR_QUAD_CurrentVersionRun_8615 {
  strings:
    $key_8615 = { d5 7a [2] f1 74 [2] da 58 [2] f4 7a [2] e0 61 [2] ef 7b [2] f1 66 [2] f3 67 [2] e8 61 [2] f4 66 [2] e8 49 }

  condition:
    any of them
}