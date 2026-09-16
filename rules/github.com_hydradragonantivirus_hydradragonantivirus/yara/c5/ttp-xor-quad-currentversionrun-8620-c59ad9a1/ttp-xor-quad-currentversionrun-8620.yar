rule TTP_XOR_QUAD_CurrentVersionRun_8620 {
  strings:
    $key_8620 = { d5 4f [2] f1 41 [2] da 6d [2] f4 4f [2] e0 54 [2] ef 4e [2] f1 53 [2] f3 52 [2] e8 54 [2] f4 53 [2] e8 7c }

  condition:
    any of them
}