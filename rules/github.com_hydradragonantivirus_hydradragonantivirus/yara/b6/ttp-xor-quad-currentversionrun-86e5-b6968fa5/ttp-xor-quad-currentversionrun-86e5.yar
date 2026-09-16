rule TTP_XOR_QUAD_CurrentVersionRun_86e5 {
  strings:
    $key_86e5 = { d5 8a [2] f1 84 [2] da a8 [2] f4 8a [2] e0 91 [2] ef 8b [2] f1 96 [2] f3 97 [2] e8 91 [2] f4 96 [2] e8 b9 }

  condition:
    any of them
}