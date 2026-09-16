rule TTP_XOR_QUAD_CurrentVersionRun_8666 {
  strings:
    $key_8666 = { d5 09 [2] f1 07 [2] da 2b [2] f4 09 [2] e0 12 [2] ef 08 [2] f1 15 [2] f3 14 [2] e8 12 [2] f4 15 [2] e8 3a }

  condition:
    any of them
}