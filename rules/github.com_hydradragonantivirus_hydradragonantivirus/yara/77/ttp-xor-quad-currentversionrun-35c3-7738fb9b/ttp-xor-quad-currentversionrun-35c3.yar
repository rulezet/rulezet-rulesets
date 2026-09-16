rule TTP_XOR_QUAD_CurrentVersionRun_35c3 {
  strings:
    $key_35c3 = { 66 ac [2] 42 a2 [2] 69 8e [2] 47 ac [2] 53 b7 [2] 5c ad [2] 42 b0 [2] 40 b1 [2] 5b b7 [2] 47 b0 [2] 5b 9f }

  condition:
    any of them
}