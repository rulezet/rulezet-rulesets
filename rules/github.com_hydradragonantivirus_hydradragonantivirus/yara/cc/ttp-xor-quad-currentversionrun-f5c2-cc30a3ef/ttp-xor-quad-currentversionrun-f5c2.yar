rule TTP_XOR_QUAD_CurrentVersionRun_f5c2 {
  strings:
    $key_f5c2 = { a6 ad [2] 82 a3 [2] a9 8f [2] 87 ad [2] 93 b6 [2] 9c ac [2] 82 b1 [2] 80 b0 [2] 9b b6 [2] 87 b1 [2] 9b 9e }

  condition:
    any of them
}