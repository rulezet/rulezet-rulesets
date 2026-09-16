rule TTP_XOR_QUAD_CurrentVersionRun_8622 {
  strings:
    $key_8622 = { d5 4d [2] f1 43 [2] da 6f [2] f4 4d [2] e0 56 [2] ef 4c [2] f1 51 [2] f3 50 [2] e8 56 [2] f4 51 [2] e8 7e }

  condition:
    any of them
}