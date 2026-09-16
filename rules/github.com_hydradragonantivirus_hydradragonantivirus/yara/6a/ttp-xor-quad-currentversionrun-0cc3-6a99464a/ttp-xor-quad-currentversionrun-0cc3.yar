rule TTP_XOR_QUAD_CurrentVersionRun_0cc3 {
  strings:
    $key_0cc3 = { 5f ac [2] 7b a2 [2] 50 8e [2] 7e ac [2] 6a b7 [2] 65 ad [2] 7b b0 [2] 79 b1 [2] 62 b7 [2] 7e b0 [2] 62 9f }

  condition:
    any of them
}