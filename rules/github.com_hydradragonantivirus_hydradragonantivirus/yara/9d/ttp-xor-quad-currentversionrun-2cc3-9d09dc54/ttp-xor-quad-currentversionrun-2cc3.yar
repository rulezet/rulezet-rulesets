rule TTP_XOR_QUAD_CurrentVersionRun_2cc3 {
  strings:
    $key_2cc3 = { 7f ac [2] 5b a2 [2] 70 8e [2] 5e ac [2] 4a b7 [2] 45 ad [2] 5b b0 [2] 59 b1 [2] 42 b7 [2] 5e b0 [2] 42 9f }

  condition:
    any of them
}