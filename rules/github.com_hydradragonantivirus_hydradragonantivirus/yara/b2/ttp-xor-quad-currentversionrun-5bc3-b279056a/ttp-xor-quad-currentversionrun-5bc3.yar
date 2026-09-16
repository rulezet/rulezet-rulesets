rule TTP_XOR_QUAD_CurrentVersionRun_5bc3 {
  strings:
    $key_5bc3 = { 08 ac [2] 2c a2 [2] 07 8e [2] 29 ac [2] 3d b7 [2] 32 ad [2] 2c b0 [2] 2e b1 [2] 35 b7 [2] 29 b0 [2] 35 9f }

  condition:
    any of them
}