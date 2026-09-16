rule TTP_XOR_QUAD_CurrentVersionRun_86fb {
  strings:
    $key_86fb = { d5 94 [2] f1 9a [2] da b6 [2] f4 94 [2] e0 8f [2] ef 95 [2] f1 88 [2] f3 89 [2] e8 8f [2] f4 88 [2] e8 a7 }

  condition:
    any of them
}