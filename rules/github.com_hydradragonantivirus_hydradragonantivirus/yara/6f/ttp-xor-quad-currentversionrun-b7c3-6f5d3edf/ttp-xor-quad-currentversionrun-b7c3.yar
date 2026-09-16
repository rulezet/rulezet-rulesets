rule TTP_XOR_QUAD_CurrentVersionRun_b7c3 {
  strings:
    $key_b7c3 = { e4 ac [2] c0 a2 [2] eb 8e [2] c5 ac [2] d1 b7 [2] de ad [2] c0 b0 [2] c2 b1 [2] d9 b7 [2] c5 b0 [2] d9 9f }

  condition:
    any of them
}