rule TTP_XOR_QUAD_CurrentVersionRun_86d7 {
  strings:
    $key_86d7 = { d5 b8 [2] f1 b6 [2] da 9a [2] f4 b8 [2] e0 a3 [2] ef b9 [2] f1 a4 [2] f3 a5 [2] e8 a3 [2] f4 a4 [2] e8 8b }

  condition:
    any of them
}