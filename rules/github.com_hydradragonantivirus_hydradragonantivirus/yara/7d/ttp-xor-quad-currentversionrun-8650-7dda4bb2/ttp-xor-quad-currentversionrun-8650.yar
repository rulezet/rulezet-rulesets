rule TTP_XOR_QUAD_CurrentVersionRun_8650 {
  strings:
    $key_8650 = { d5 3f [2] f1 31 [2] da 1d [2] f4 3f [2] e0 24 [2] ef 3e [2] f1 23 [2] f3 22 [2] e8 24 [2] f4 23 [2] e8 0c }

  condition:
    any of them
}