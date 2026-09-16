rule TTP_XOR_QUAD_CurrentVersionRun_08c3 {
  strings:
    $key_08c3 = { 5b ac [2] 7f a2 [2] 54 8e [2] 7a ac [2] 6e b7 [2] 61 ad [2] 7f b0 [2] 7d b1 [2] 66 b7 [2] 7a b0 [2] 66 9f }

  condition:
    any of them
}