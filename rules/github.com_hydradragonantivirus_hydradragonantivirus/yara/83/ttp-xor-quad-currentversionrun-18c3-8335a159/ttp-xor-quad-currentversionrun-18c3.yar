rule TTP_XOR_QUAD_CurrentVersionRun_18c3 {
  strings:
    $key_18c3 = { 4b ac [2] 6f a2 [2] 44 8e [2] 6a ac [2] 7e b7 [2] 71 ad [2] 6f b0 [2] 6d b1 [2] 76 b7 [2] 6a b0 [2] 76 9f }

  condition:
    any of them
}