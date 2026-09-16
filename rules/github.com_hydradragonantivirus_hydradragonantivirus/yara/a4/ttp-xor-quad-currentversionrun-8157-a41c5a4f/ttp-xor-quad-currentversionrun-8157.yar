rule TTP_XOR_QUAD_CurrentVersionRun_8157 {
  strings:
    $key_8157 = { d2 38 [2] f6 36 [2] dd 1a [2] f3 38 [2] e7 23 [2] e8 39 [2] f6 24 [2] f4 25 [2] ef 23 [2] f3 24 [2] ef 0b }

  condition:
    any of them
}