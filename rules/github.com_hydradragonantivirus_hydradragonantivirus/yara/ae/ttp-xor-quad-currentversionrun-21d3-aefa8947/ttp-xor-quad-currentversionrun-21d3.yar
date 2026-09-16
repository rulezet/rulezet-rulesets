rule TTP_XOR_QUAD_CurrentVersionRun_21d3 {
  strings:
    $key_21d3 = { 72 bc [2] 56 b2 [2] 7d 9e [2] 53 bc [2] 47 a7 [2] 48 bd [2] 56 a0 [2] 54 a1 [2] 4f a7 [2] 53 a0 [2] 4f 8f }

  condition:
    any of them
}