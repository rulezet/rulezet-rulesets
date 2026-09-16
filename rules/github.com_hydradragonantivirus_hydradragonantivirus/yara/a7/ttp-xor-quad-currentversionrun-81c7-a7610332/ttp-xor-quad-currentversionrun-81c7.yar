rule TTP_XOR_QUAD_CurrentVersionRun_81c7 {
  strings:
    $key_81c7 = { d2 a8 [2] f6 a6 [2] dd 8a [2] f3 a8 [2] e7 b3 [2] e8 a9 [2] f6 b4 [2] f4 b5 [2] ef b3 [2] f3 b4 [2] ef 9b }

  condition:
    any of them
}