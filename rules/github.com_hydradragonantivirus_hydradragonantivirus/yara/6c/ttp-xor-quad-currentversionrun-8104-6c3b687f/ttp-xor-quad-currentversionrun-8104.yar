rule TTP_XOR_QUAD_CurrentVersionRun_8104 {
  strings:
    $key_8104 = { d2 6b [2] f6 65 [2] dd 49 [2] f3 6b [2] e7 70 [2] e8 6a [2] f6 77 [2] f4 76 [2] ef 70 [2] f3 77 [2] ef 58 }

  condition:
    any of them
}