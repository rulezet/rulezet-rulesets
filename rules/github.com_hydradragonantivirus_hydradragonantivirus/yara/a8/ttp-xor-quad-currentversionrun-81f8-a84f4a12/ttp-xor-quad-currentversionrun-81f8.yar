rule TTP_XOR_QUAD_CurrentVersionRun_81f8 {
  strings:
    $key_81f8 = { d2 97 [2] f6 99 [2] dd b5 [2] f3 97 [2] e7 8c [2] e8 96 [2] f6 8b [2] f4 8a [2] ef 8c [2] f3 8b [2] ef a4 }

  condition:
    any of them
}