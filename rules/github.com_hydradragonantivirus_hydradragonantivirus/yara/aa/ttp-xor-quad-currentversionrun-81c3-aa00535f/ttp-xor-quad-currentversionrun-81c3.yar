rule TTP_XOR_QUAD_CurrentVersionRun_81c3 {
  strings:
    $key_81c3 = { d2 ac [2] f6 a2 [2] dd 8e [2] f3 ac [2] e7 b7 [2] e8 ad [2] f6 b0 [2] f4 b1 [2] ef b7 [2] f3 b0 [2] ef 9f }

  condition:
    any of them
}