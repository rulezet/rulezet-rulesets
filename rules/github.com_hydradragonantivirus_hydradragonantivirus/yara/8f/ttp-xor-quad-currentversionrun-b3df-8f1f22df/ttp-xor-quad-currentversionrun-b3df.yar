rule TTP_XOR_QUAD_CurrentVersionRun_b3df {
  strings:
    $key_b3df = { e0 b0 [2] c4 be [2] ef 92 [2] c1 b0 [2] d5 ab [2] da b1 [2] c4 ac [2] c6 ad [2] dd ab [2] c1 ac [2] dd 83 }

  condition:
    any of them
}