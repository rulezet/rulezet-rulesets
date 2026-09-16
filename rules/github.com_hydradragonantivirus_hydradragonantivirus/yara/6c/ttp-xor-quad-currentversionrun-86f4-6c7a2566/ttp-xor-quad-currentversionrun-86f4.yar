rule TTP_XOR_QUAD_CurrentVersionRun_86f4 {
  strings:
    $key_86f4 = { d5 9b [2] f1 95 [2] da b9 [2] f4 9b [2] e0 80 [2] ef 9a [2] f1 87 [2] f3 86 [2] e8 80 [2] f4 87 [2] e8 a8 }

  condition:
    any of them
}