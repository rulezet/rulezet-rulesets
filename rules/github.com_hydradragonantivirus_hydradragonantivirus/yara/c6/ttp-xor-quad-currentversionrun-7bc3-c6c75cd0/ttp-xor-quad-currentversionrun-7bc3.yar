rule TTP_XOR_QUAD_CurrentVersionRun_7bc3 {
  strings:
    $key_7bc3 = { 28 ac [2] 0c a2 [2] 27 8e [2] 09 ac [2] 1d b7 [2] 12 ad [2] 0c b0 [2] 0e b1 [2] 15 b7 [2] 09 b0 [2] 15 9f }

  condition:
    any of them
}