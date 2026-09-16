rule TTP_XOR_QUAD_CurrentVersionRun_3cc3 {
  strings:
    $key_3cc3 = { 6f ac [2] 4b a2 [2] 60 8e [2] 4e ac [2] 5a b7 [2] 55 ad [2] 4b b0 [2] 49 b1 [2] 52 b7 [2] 4e b0 [2] 52 9f }

  condition:
    any of them
}