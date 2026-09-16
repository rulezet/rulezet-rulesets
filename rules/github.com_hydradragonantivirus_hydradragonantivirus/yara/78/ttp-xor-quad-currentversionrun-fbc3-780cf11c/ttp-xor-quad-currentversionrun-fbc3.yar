rule TTP_XOR_QUAD_CurrentVersionRun_fbc3 {
  strings:
    $key_fbc3 = { a8 ac [2] 8c a2 [2] a7 8e [2] 89 ac [2] 9d b7 [2] 92 ad [2] 8c b0 [2] 8e b1 [2] 95 b7 [2] 89 b0 [2] 95 9f }

  condition:
    any of them
}