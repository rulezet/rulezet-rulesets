rule TTP_XOR_QUAD_CurrentVersionRun_8124 {
  strings:
    $key_8124 = { d2 4b [2] f6 45 [2] dd 69 [2] f3 4b [2] e7 50 [2] e8 4a [2] f6 57 [2] f4 56 [2] ef 50 [2] f3 57 [2] ef 78 }

  condition:
    any of them
}