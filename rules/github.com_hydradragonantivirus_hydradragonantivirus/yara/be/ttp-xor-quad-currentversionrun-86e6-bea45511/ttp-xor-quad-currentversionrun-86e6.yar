rule TTP_XOR_QUAD_CurrentVersionRun_86e6 {
  strings:
    $key_86e6 = { d5 89 [2] f1 87 [2] da ab [2] f4 89 [2] e0 92 [2] ef 88 [2] f1 95 [2] f3 94 [2] e8 92 [2] f4 95 [2] e8 ba }

  condition:
    any of them
}