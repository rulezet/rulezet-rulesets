rule TTP_XOR_QUAD_CurrentVersionRun_86fa {
  strings:
    $key_86fa = { d5 95 [2] f1 9b [2] da b7 [2] f4 95 [2] e0 8e [2] ef 94 [2] f1 89 [2] f3 88 [2] e8 8e [2] f4 89 [2] e8 a6 }

  condition:
    any of them
}