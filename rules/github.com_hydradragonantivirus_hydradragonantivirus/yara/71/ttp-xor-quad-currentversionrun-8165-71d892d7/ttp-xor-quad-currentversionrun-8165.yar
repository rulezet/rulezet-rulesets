rule TTP_XOR_QUAD_CurrentVersionRun_8165 {
  strings:
    $key_8165 = { d2 0a [2] f6 04 [2] dd 28 [2] f3 0a [2] e7 11 [2] e8 0b [2] f6 16 [2] f4 17 [2] ef 11 [2] f3 16 [2] ef 39 }

  condition:
    any of them
}