rule TTP_XOR_QUAD_CurrentVersionRun_ecd2 {
  strings:
    $key_ecd2 = { bf bd [2] 9b b3 [2] b0 9f [2] 9e bd [2] 8a a6 [2] 85 bc [2] 9b a1 [2] 99 a0 [2] 82 a6 [2] 9e a1 [2] 82 8e }

  condition:
    any of them
}