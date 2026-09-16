rule TTP_XOR_QUAD_CurrentVersionRun_dfd3 {
  strings:
    $key_dfd3 = { 8c bc [2] a8 b2 [2] 83 9e [2] ad bc [2] b9 a7 [2] b6 bd [2] a8 a0 [2] aa a1 [2] b1 a7 [2] ad a0 [2] b1 8f }

  condition:
    any of them
}