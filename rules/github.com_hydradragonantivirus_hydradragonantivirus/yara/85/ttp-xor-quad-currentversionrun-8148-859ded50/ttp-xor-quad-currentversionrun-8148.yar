rule TTP_XOR_QUAD_CurrentVersionRun_8148 {
  strings:
    $key_8148 = { d2 27 [2] f6 29 [2] dd 05 [2] f3 27 [2] e7 3c [2] e8 26 [2] f6 3b [2] f4 3a [2] ef 3c [2] f3 3b [2] ef 14 }

  condition:
    any of them
}