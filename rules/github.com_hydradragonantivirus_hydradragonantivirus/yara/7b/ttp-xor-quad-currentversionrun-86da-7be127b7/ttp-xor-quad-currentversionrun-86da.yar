rule TTP_XOR_QUAD_CurrentVersionRun_86da {
  strings:
    $key_86da = { d5 b5 [2] f1 bb [2] da 97 [2] f4 b5 [2] e0 ae [2] ef b4 [2] f1 a9 [2] f3 a8 [2] e8 ae [2] f4 a9 [2] e8 86 }

  condition:
    any of them
}