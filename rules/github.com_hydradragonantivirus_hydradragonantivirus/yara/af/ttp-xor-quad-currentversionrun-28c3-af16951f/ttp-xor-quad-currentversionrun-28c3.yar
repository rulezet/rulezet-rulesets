rule TTP_XOR_QUAD_CurrentVersionRun_28c3 {
  strings:
    $key_28c3 = { 7b ac [2] 5f a2 [2] 74 8e [2] 5a ac [2] 4e b7 [2] 41 ad [2] 5f b0 [2] 5d b1 [2] 46 b7 [2] 5a b0 [2] 46 9f }

  condition:
    any of them
}