rule TTP_XOR_QUAD_CurrentVersionRun_867d {
  strings:
    $key_867d = { d5 12 [2] f1 1c [2] da 30 [2] f4 12 [2] e0 09 [2] ef 13 [2] f1 0e [2] f3 0f [2] e8 09 [2] f4 0e [2] e8 21 }

  condition:
    any of them
}