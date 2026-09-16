rule TTP_XOR_QUAD_CurrentVersionRun_8105 {
  strings:
    $key_8105 = { d2 6a [2] f6 64 [2] dd 48 [2] f3 6a [2] e7 71 [2] e8 6b [2] f6 76 [2] f4 77 [2] ef 71 [2] f3 76 [2] ef 59 }

  condition:
    any of them
}