rule TTP_XOR_QUAD_CurrentVersionRun_4ec3 {
  strings:
    $key_4ec3 = { 1d ac [2] 39 a2 [2] 12 8e [2] 3c ac [2] 28 b7 [2] 27 ad [2] 39 b0 [2] 3b b1 [2] 20 b7 [2] 3c b0 [2] 20 9f }

  condition:
    any of them
}