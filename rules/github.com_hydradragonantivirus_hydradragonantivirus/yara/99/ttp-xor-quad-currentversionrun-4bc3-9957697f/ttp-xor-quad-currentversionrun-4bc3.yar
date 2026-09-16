rule TTP_XOR_QUAD_CurrentVersionRun_4bc3 {
  strings:
    $key_4bc3 = { 18 ac [2] 3c a2 [2] 17 8e [2] 39 ac [2] 2d b7 [2] 22 ad [2] 3c b0 [2] 3e b1 [2] 25 b7 [2] 39 b0 [2] 25 9f }

  condition:
    any of them
}