rule TTP_XOR_QUAD_CurrentVersionRun_81c2 {
  strings:
    $key_81c2 = { d2 ad [2] f6 a3 [2] dd 8f [2] f3 ad [2] e7 b6 [2] e8 ac [2] f6 b1 [2] f4 b0 [2] ef b6 [2] f3 b1 [2] ef 9e }

  condition:
    any of them
}