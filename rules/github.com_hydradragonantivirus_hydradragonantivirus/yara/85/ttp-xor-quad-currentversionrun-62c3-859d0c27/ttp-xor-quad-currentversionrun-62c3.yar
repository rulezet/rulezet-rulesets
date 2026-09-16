rule TTP_XOR_QUAD_CurrentVersionRun_62c3 {
  strings:
    $key_62c3 = { 31 ac [2] 15 a2 [2] 3e 8e [2] 10 ac [2] 04 b7 [2] 0b ad [2] 15 b0 [2] 17 b1 [2] 0c b7 [2] 10 b0 [2] 0c 9f }

  condition:
    any of them
}