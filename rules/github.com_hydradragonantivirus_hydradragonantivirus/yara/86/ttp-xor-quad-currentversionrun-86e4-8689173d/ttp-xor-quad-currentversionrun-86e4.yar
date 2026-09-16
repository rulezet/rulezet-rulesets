rule TTP_XOR_QUAD_CurrentVersionRun_86e4 {
  strings:
    $key_86e4 = { d5 8b [2] f1 85 [2] da a9 [2] f4 8b [2] e0 90 [2] ef 8a [2] f1 97 [2] f3 96 [2] e8 90 [2] f4 97 [2] e8 b8 }

  condition:
    any of them
}