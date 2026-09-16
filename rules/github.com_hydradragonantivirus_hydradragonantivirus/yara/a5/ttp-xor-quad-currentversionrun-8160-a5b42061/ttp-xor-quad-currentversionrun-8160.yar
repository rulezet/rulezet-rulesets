rule TTP_XOR_QUAD_CurrentVersionRun_8160 {
  strings:
    $key_8160 = { d2 0f [2] f6 01 [2] dd 2d [2] f3 0f [2] e7 14 [2] e8 0e [2] f6 13 [2] f4 12 [2] ef 14 [2] f3 13 [2] ef 3c }

  condition:
    any of them
}