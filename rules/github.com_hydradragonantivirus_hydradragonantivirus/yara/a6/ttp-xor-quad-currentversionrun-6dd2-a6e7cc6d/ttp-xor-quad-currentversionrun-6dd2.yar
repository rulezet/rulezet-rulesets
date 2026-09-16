rule TTP_XOR_QUAD_CurrentVersionRun_6dd2 {
  strings:
    $key_6dd2 = { 3e bd [2] 1a b3 [2] 31 9f [2] 1f bd [2] 0b a6 [2] 04 bc [2] 1a a1 [2] 18 a0 [2] 03 a6 [2] 1f a1 [2] 03 8e }

  condition:
    any of them
}