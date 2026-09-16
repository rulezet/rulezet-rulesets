rule TTP_XOR_QUAD_CurrentVersionRun_f9c3 {
  strings:
    $key_f9c3 = { aa ac [2] 8e a2 [2] a5 8e [2] 8b ac [2] 9f b7 [2] 90 ad [2] 8e b0 [2] 8c b1 [2] 97 b7 [2] 8b b0 [2] 97 9f }

  condition:
    any of them
}