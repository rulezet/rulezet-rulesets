rule TTP_XOR_QUAD_CurrentVersionRun_8637 {
  strings:
    $key_8637 = { d5 58 [2] f1 56 [2] da 7a [2] f4 58 [2] e0 43 [2] ef 59 [2] f1 44 [2] f3 45 [2] e8 43 [2] f4 44 [2] e8 6b }

  condition:
    any of them
}