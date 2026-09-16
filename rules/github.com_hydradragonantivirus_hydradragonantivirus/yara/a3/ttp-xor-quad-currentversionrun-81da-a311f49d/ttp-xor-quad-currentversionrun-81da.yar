rule TTP_XOR_QUAD_CurrentVersionRun_81da {
  strings:
    $key_81da = { d2 b5 [2] f6 bb [2] dd 97 [2] f3 b5 [2] e7 ae [2] e8 b4 [2] f6 a9 [2] f4 a8 [2] ef ae [2] f3 a9 [2] ef 86 }

  condition:
    any of them
}