rule TTP_XOR_QUAD_CurrentVersionRun_8114 {
  strings:
    $key_8114 = { d2 7b [2] f6 75 [2] dd 59 [2] f3 7b [2] e7 60 [2] e8 7a [2] f6 67 [2] f4 66 [2] ef 60 [2] f3 67 [2] ef 48 }

  condition:
    any of them
}