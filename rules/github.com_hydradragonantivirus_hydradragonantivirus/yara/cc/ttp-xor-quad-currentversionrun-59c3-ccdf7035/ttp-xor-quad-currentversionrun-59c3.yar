rule TTP_XOR_QUAD_CurrentVersionRun_59c3 {
  strings:
    $key_59c3 = { 0a ac [2] 2e a2 [2] 05 8e [2] 2b ac [2] 3f b7 [2] 30 ad [2] 2e b0 [2] 2c b1 [2] 37 b7 [2] 2b b0 [2] 37 9f }

  condition:
    any of them
}