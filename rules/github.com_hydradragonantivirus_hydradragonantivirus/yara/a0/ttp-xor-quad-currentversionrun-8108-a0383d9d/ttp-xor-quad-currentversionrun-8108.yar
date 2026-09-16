rule TTP_XOR_QUAD_CurrentVersionRun_8108 {
  strings:
    $key_8108 = { d2 67 [2] f6 69 [2] dd 45 [2] f3 67 [2] e7 7c [2] e8 66 [2] f6 7b [2] f4 7a [2] ef 7c [2] f3 7b [2] ef 54 }

  condition:
    any of them
}