rule TTP_XOR_QUAD_CurrentVersionRun_8178 {
  strings:
    $key_8178 = { d2 17 [2] f6 19 [2] dd 35 [2] f3 17 [2] e7 0c [2] e8 16 [2] f6 0b [2] f4 0a [2] ef 0c [2] f3 0b [2] ef 24 }

  condition:
    any of them
}