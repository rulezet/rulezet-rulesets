rule TTP_XOR_QUAD_CurrentVersionRun_5cc3 {
  strings:
    $key_5cc3 = { 0f ac [2] 2b a2 [2] 00 8e [2] 2e ac [2] 3a b7 [2] 35 ad [2] 2b b0 [2] 29 b1 [2] 32 b7 [2] 2e b0 [2] 32 9f }

  condition:
    any of them
}