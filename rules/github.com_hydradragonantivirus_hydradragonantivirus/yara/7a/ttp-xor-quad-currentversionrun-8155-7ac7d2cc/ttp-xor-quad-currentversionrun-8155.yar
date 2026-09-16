rule TTP_XOR_QUAD_CurrentVersionRun_8155 {
  strings:
    $key_8155 = { d2 3a [2] f6 34 [2] dd 18 [2] f3 3a [2] e7 21 [2] e8 3b [2] f6 26 [2] f4 27 [2] ef 21 [2] f3 26 [2] ef 09 }

  condition:
    any of them
}