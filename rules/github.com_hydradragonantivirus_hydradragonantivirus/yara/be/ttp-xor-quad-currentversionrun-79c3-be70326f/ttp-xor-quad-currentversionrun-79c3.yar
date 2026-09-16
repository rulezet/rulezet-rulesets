rule TTP_XOR_QUAD_CurrentVersionRun_79c3 {
  strings:
    $key_79c3 = { 2a ac [2] 0e a2 [2] 25 8e [2] 0b ac [2] 1f b7 [2] 10 ad [2] 0e b0 [2] 0c b1 [2] 17 b7 [2] 0b b0 [2] 17 9f }

  condition:
    any of them
}