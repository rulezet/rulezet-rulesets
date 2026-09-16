rule TTP_XOR_QUAD_CurrentVersionRun_86d5 {
  strings:
    $key_86d5 = { d5 ba [2] f1 b4 [2] da 98 [2] f4 ba [2] e0 a1 [2] ef bb [2] f1 a6 [2] f3 a7 [2] e8 a1 [2] f4 a6 [2] e8 89 }

  condition:
    any of them
}