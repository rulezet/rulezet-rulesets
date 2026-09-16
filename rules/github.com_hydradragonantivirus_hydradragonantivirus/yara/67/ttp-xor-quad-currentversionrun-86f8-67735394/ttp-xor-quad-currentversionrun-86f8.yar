rule TTP_XOR_QUAD_CurrentVersionRun_86f8 {
  strings:
    $key_86f8 = { d5 97 [2] f1 99 [2] da b5 [2] f4 97 [2] e0 8c [2] ef 96 [2] f1 8b [2] f3 8a [2] e8 8c [2] f4 8b [2] e8 a4 }

  condition:
    any of them
}