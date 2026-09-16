rule TTP_XOR_QUAD_CurrentVersionRun_8127 {
  strings:
    $key_8127 = { d2 48 [2] f6 46 [2] dd 6a [2] f3 48 [2] e7 53 [2] e8 49 [2] f6 54 [2] f4 55 [2] ef 53 [2] f3 54 [2] ef 7b }

  condition:
    any of them
}