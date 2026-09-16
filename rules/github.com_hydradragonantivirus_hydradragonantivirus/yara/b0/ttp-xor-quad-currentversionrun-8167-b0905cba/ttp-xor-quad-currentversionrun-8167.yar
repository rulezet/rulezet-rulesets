rule TTP_XOR_QUAD_CurrentVersionRun_8167 {
  strings:
    $key_8167 = { d2 08 [2] f6 06 [2] dd 2a [2] f3 08 [2] e7 13 [2] e8 09 [2] f6 14 [2] f4 15 [2] ef 13 [2] f3 14 [2] ef 3b }

  condition:
    any of them
}