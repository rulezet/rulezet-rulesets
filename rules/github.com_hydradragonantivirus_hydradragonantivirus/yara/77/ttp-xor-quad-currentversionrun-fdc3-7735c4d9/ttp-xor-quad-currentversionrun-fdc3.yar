rule TTP_XOR_QUAD_CurrentVersionRun_fdc3 {
  strings:
    $key_fdc3 = { ae ac [2] 8a a2 [2] a1 8e [2] 8f ac [2] 9b b7 [2] 94 ad [2] 8a b0 [2] 88 b1 [2] 93 b7 [2] 8f b0 [2] 93 9f }

  condition:
    any of them
}