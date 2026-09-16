rule TTP_XOR_QUAD_CurrentVersionRun_8125 {
  strings:
    $key_8125 = { d2 4a [2] f6 44 [2] dd 68 [2] f3 4a [2] e7 51 [2] e8 4b [2] f6 56 [2] f4 57 [2] ef 51 [2] f3 56 [2] ef 79 }

  condition:
    any of them
}