rule TTP_XOR_QUAD_CurrentVersionRun_8642 {
  strings:
    $key_8642 = { d5 2d [2] f1 23 [2] da 0f [2] f4 2d [2] e0 36 [2] ef 2c [2] f1 31 [2] f3 30 [2] e8 36 [2] f4 31 [2] e8 1e }

  condition:
    any of them
}