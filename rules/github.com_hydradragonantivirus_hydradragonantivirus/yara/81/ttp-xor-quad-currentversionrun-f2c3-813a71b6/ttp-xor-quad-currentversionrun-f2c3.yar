rule TTP_XOR_QUAD_CurrentVersionRun_f2c3 {
  strings:
    $key_f2c3 = { a1 ac [2] 85 a2 [2] ae 8e [2] 80 ac [2] 94 b7 [2] 9b ad [2] 85 b0 [2] 87 b1 [2] 9c b7 [2] 80 b0 [2] 9c 9f }

  condition:
    any of them
}