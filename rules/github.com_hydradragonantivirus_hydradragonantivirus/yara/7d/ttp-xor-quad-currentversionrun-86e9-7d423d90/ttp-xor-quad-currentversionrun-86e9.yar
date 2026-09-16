rule TTP_XOR_QUAD_CurrentVersionRun_86e9 {
  strings:
    $key_86e9 = { d5 86 [2] f1 88 [2] da a4 [2] f4 86 [2] e0 9d [2] ef 87 [2] f1 9a [2] f3 9b [2] e8 9d [2] f4 9a [2] e8 b5 }

  condition:
    any of them
}