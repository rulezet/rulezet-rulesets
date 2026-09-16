rule TTP_XOR_QUAD_CurrentVersionRun_2ec3 {
  strings:
    $key_2ec3 = { 7d ac [2] 59 a2 [2] 72 8e [2] 5c ac [2] 48 b7 [2] 47 ad [2] 59 b0 [2] 5b b1 [2] 40 b7 [2] 5c b0 [2] 40 9f }

  condition:
    any of them
}