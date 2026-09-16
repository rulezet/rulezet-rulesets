rule TTP_XOR_QUAD_CurrentVersionRun_29c3 {
  strings:
    $key_29c3 = { 7a ac [2] 5e a2 [2] 75 8e [2] 5b ac [2] 4f b7 [2] 40 ad [2] 5e b0 [2] 5c b1 [2] 47 b7 [2] 5b b0 [2] 47 9f }

  condition:
    any of them
}