rule TTP_XOR_QUAD_CurrentVersionRun_38c3 {
  strings:
    $key_38c3 = { 6b ac [2] 4f a2 [2] 64 8e [2] 4a ac [2] 5e b7 [2] 51 ad [2] 4f b0 [2] 4d b1 [2] 56 b7 [2] 4a b0 [2] 56 9f }

  condition:
    any of them
}