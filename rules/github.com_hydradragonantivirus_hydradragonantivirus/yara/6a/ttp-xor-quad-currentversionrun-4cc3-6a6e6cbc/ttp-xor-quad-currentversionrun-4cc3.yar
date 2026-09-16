rule TTP_XOR_QUAD_CurrentVersionRun_4cc3 {
  strings:
    $key_4cc3 = { 1f ac [2] 3b a2 [2] 10 8e [2] 3e ac [2] 2a b7 [2] 25 ad [2] 3b b0 [2] 39 b1 [2] 22 b7 [2] 3e b0 [2] 22 9f }

  condition:
    any of them
}