rule TTP_XOR_QUAD_CurrentVersionRun_86c3 {
  strings:
    $key_86c3 = { d5 ac [2] f1 a2 [2] da 8e [2] f4 ac [2] e0 b7 [2] ef ad [2] f1 b0 [2] f3 b1 [2] e8 b7 [2] f4 b0 [2] e8 9f }

  condition:
    any of them
}