rule TTP_XOR_QUAD_CurrentVersionRun_86f3 {
  strings:
    $key_86f3 = { d5 9c [2] f1 92 [2] da be [2] f4 9c [2] e0 87 [2] ef 9d [2] f1 80 [2] f3 81 [2] e8 87 [2] f4 80 [2] e8 af }

  condition:
    any of them
}