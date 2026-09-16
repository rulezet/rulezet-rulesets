rule TTP_XOR_QUAD_CurrentVersionRun_65c3 {
  strings:
    $key_65c3 = { 36 ac [2] 12 a2 [2] 39 8e [2] 17 ac [2] 03 b7 [2] 0c ad [2] 12 b0 [2] 10 b1 [2] 0b b7 [2] 17 b0 [2] 0b 9f }

  condition:
    any of them
}