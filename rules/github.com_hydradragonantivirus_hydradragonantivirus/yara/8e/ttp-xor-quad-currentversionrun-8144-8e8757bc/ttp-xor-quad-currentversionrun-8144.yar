rule TTP_XOR_QUAD_CurrentVersionRun_8144 {
  strings:
    $key_8144 = { d2 2b [2] f6 25 [2] dd 09 [2] f3 2b [2] e7 30 [2] e8 2a [2] f6 37 [2] f4 36 [2] ef 30 [2] f3 37 [2] ef 18 }

  condition:
    any of them
}