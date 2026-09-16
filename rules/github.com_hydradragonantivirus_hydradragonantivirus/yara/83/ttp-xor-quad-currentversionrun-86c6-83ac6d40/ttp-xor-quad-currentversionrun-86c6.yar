rule TTP_XOR_QUAD_CurrentVersionRun_86c6 {
  strings:
    $key_86c6 = { d5 a9 [2] f1 a7 [2] da 8b [2] f4 a9 [2] e0 b2 [2] ef a8 [2] f1 b5 [2] f3 b4 [2] e8 b2 [2] f4 b5 [2] e8 9a }

  condition:
    any of them
}