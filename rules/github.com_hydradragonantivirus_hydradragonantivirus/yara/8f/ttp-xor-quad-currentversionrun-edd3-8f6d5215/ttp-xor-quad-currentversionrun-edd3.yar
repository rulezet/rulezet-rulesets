rule TTP_XOR_QUAD_CurrentVersionRun_edd3 {
  strings:
    $key_edd3 = { be bc [2] 9a b2 [2] b1 9e [2] 9f bc [2] 8b a7 [2] 84 bd [2] 9a a0 [2] 98 a1 [2] 83 a7 [2] 9f a0 [2] 83 8f }

  condition:
    any of them
}