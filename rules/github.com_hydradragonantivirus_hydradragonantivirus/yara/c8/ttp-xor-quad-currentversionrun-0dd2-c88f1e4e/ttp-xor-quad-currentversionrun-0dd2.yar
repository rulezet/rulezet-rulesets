rule TTP_XOR_QUAD_CurrentVersionRun_0dd2 {
  strings:
    $key_0dd2 = { 5e bd [2] 7a b3 [2] 51 9f [2] 7f bd [2] 6b a6 [2] 64 bc [2] 7a a1 [2] 78 a0 [2] 63 a6 [2] 7f a1 [2] 63 8e }

  condition:
    any of them
}