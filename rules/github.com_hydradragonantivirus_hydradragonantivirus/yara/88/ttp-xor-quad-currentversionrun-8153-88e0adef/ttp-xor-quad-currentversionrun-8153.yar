rule TTP_XOR_QUAD_CurrentVersionRun_8153 {
  strings:
    $key_8153 = { d2 3c [2] f6 32 [2] dd 1e [2] f3 3c [2] e7 27 [2] e8 3d [2] f6 20 [2] f4 21 [2] ef 27 [2] f3 20 [2] ef 0f }

  condition:
    any of them
}