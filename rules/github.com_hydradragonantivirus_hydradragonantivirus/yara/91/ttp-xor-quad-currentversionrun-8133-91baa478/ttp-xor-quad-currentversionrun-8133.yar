rule TTP_XOR_QUAD_CurrentVersionRun_8133 {
  strings:
    $key_8133 = { d2 5c [2] f6 52 [2] dd 7e [2] f3 5c [2] e7 47 [2] e8 5d [2] f6 40 [2] f4 41 [2] ef 47 [2] f3 40 [2] ef 6f }

  condition:
    any of them
}