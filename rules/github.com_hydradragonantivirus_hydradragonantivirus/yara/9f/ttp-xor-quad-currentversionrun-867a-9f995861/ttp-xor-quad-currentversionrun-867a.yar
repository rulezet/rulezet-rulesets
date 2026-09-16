rule TTP_XOR_QUAD_CurrentVersionRun_867a {
  strings:
    $key_867a = { d5 15 [2] f1 1b [2] da 37 [2] f4 15 [2] e0 0e [2] ef 14 [2] f1 09 [2] f3 08 [2] e8 0e [2] f4 09 [2] e8 26 }

  condition:
    any of them
}