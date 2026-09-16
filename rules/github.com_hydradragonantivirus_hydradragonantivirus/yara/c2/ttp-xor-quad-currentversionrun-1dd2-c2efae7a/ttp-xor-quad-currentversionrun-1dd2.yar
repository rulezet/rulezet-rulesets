rule TTP_XOR_QUAD_CurrentVersionRun_1dd2 {
  strings:
    $key_1dd2 = { 4e bd [2] 6a b3 [2] 41 9f [2] 6f bd [2] 7b a6 [2] 74 bc [2] 6a a1 [2] 68 a0 [2] 73 a6 [2] 6f a1 [2] 73 8e }

  condition:
    any of them
}