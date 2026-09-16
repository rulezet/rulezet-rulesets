rule TTP_XOR_QUAD_CurrentVersionRun_8106 {
  strings:
    $key_8106 = { d2 69 [2] f6 67 [2] dd 4b [2] f3 69 [2] e7 72 [2] e8 68 [2] f6 75 [2] f4 74 [2] ef 72 [2] f3 75 [2] ef 5a }

  condition:
    any of them
}