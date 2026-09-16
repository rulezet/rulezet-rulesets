rule TTP_XOR_QUAD_CurrentVersionRun_12c3 {
  strings:
    $key_12c3 = { 41 ac [2] 65 a2 [2] 4e 8e [2] 60 ac [2] 74 b7 [2] 7b ad [2] 65 b0 [2] 67 b1 [2] 7c b7 [2] 60 b0 [2] 7c 9f }

  condition:
    any of them
}