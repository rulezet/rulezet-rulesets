rule TTP_XOR_QUAD_CurrentVersionRun_8113 {
  strings:
    $key_8113 = { d2 7c [2] f6 72 [2] dd 5e [2] f3 7c [2] e7 67 [2] e8 7d [2] f6 60 [2] f4 61 [2] ef 67 [2] f3 60 [2] ef 4f }

  condition:
    any of them
}