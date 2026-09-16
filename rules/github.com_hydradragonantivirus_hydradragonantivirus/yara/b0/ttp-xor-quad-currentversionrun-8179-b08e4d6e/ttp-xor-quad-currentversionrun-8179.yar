rule TTP_XOR_QUAD_CurrentVersionRun_8179 {
  strings:
    $key_8179 = { d2 16 [2] f6 18 [2] dd 34 [2] f3 16 [2] e7 0d [2] e8 17 [2] f6 0a [2] f4 0b [2] ef 0d [2] f3 0a [2] ef 25 }

  condition:
    any of them
}