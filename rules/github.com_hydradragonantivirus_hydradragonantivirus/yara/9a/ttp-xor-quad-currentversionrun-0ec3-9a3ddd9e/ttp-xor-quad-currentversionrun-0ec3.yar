rule TTP_XOR_QUAD_CurrentVersionRun_0ec3 {
  strings:
    $key_0ec3 = { 5d ac [2] 79 a2 [2] 52 8e [2] 7c ac [2] 68 b7 [2] 67 ad [2] 79 b0 [2] 7b b1 [2] 60 b7 [2] 7c b0 [2] 60 9f }

  condition:
    any of them
}