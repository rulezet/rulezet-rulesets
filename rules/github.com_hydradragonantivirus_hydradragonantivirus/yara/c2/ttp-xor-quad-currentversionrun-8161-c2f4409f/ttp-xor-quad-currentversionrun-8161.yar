rule TTP_XOR_QUAD_CurrentVersionRun_8161 {
  strings:
    $key_8161 = { d2 0e [2] f6 00 [2] dd 2c [2] f3 0e [2] e7 15 [2] e8 0f [2] f6 12 [2] f4 13 [2] ef 15 [2] f3 12 [2] ef 3d }

  condition:
    any of them
}