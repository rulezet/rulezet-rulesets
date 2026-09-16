rule TTP_XOR_QUAD_CurrentVersionRun_3dd2 {
  strings:
    $key_3dd2 = { 6e bd [2] 4a b3 [2] 61 9f [2] 4f bd [2] 5b a6 [2] 54 bc [2] 4a a1 [2] 48 a0 [2] 53 a6 [2] 4f a1 [2] 53 8e }

  condition:
    any of them
}