rule TTP_XOR_QUAD_CurrentVersionRun_81df {
  strings:
    $key_81df = { d2 b0 [2] f6 be [2] dd 92 [2] f3 b0 [2] e7 ab [2] e8 b1 [2] f6 ac [2] f4 ad [2] ef ab [2] f3 ac [2] ef 83 }

  condition:
    any of them
}