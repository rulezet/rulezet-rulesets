rule TTP_XOR_QUAD_CurrentVersionRun_86d4 {
  strings:
    $key_86d4 = { d5 bb [2] f1 b5 [2] da 99 [2] f4 bb [2] e0 a0 [2] ef ba [2] f1 a7 [2] f3 a6 [2] e8 a0 [2] f4 a7 [2] e8 88 }

  condition:
    any of them
}