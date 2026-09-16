rule TTP_XOR_QUAD_CurrentVersionRun_8147 {
  strings:
    $key_8147 = { d2 28 [2] f6 26 [2] dd 0a [2] f3 28 [2] e7 33 [2] e8 29 [2] f6 34 [2] f4 35 [2] ef 33 [2] f3 34 [2] ef 1b }

  condition:
    any of them
}