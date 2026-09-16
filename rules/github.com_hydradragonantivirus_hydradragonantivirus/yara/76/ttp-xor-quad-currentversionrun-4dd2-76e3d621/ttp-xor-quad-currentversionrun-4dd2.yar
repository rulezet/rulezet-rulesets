rule TTP_XOR_QUAD_CurrentVersionRun_4dd2 {
  strings:
    $key_4dd2 = { 1e bd [2] 3a b3 [2] 11 9f [2] 3f bd [2] 2b a6 [2] 24 bc [2] 3a a1 [2] 38 a0 [2] 23 a6 [2] 3f a1 [2] 23 8e }

  condition:
    any of them
}