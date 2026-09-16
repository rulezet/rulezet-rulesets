rule TTP_XOR_QUAD_CurrentVersionRun_8169 {
  strings:
    $key_8169 = { d2 06 [2] f6 08 [2] dd 24 [2] f3 06 [2] e7 1d [2] e8 07 [2] f6 1a [2] f4 1b [2] ef 1d [2] f3 1a [2] ef 35 }

  condition:
    any of them
}