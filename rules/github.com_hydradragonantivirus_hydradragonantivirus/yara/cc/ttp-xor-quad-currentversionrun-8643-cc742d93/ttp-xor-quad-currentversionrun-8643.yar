rule TTP_XOR_QUAD_CurrentVersionRun_8643 {
  strings:
    $key_8643 = { d5 2c [2] f1 22 [2] da 0e [2] f4 2c [2] e0 37 [2] ef 2d [2] f1 30 [2] f3 31 [2] e8 37 [2] f4 30 [2] e8 1f }

  condition:
    any of them
}