rule TTP_XOR_QUAD_CurrentVersionRun_8175 {
  strings:
    $key_8175 = { d2 1a [2] f6 14 [2] dd 38 [2] f3 1a [2] e7 01 [2] e8 1b [2] f6 06 [2] f4 07 [2] ef 01 [2] f3 06 [2] ef 29 }

  condition:
    any of them
}