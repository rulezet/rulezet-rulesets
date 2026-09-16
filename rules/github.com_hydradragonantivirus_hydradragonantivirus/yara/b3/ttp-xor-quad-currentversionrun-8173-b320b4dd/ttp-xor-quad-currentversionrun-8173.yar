rule TTP_XOR_QUAD_CurrentVersionRun_8173 {
  strings:
    $key_8173 = { d2 1c [2] f6 12 [2] dd 3e [2] f3 1c [2] e7 07 [2] e8 1d [2] f6 00 [2] f4 01 [2] ef 07 [2] f3 00 [2] ef 2f }

  condition:
    any of them
}