rule TTP_XOR_QUAD_CurrentVersionRun_52c3 {
  strings:
    $key_52c3 = { 01 ac [2] 25 a2 [2] 0e 8e [2] 20 ac [2] 34 b7 [2] 3b ad [2] 25 b0 [2] 27 b1 [2] 3c b7 [2] 20 b0 [2] 3c 9f }

  condition:
    any of them
}