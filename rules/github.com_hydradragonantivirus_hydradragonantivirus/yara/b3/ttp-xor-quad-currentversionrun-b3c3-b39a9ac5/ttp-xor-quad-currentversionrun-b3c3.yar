rule TTP_XOR_QUAD_CurrentVersionRun_b3c3 {
  strings:
    $key_b3c3 = { e0 ac [2] c4 a2 [2] ef 8e [2] c1 ac [2] d5 b7 [2] da ad [2] c4 b0 [2] c6 b1 [2] dd b7 [2] c1 b0 [2] dd 9f }

  condition:
    any of them
}