rule TTP_XOR_QUAD_CurrentVersionRun_8652 {
  strings:
    $key_8652 = { d5 3d [2] f1 33 [2] da 1f [2] f4 3d [2] e0 26 [2] ef 3c [2] f1 21 [2] f3 20 [2] e8 26 [2] f4 21 [2] e8 0e }

  condition:
    any of them
}