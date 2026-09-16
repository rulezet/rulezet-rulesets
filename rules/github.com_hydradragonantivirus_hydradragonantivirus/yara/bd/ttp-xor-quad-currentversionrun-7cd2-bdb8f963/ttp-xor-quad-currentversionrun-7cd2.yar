rule TTP_XOR_QUAD_CurrentVersionRun_7cd2 {
  strings:
    $key_7cd2 = { 2f bd [2] 0b b3 [2] 20 9f [2] 0e bd [2] 1a a6 [2] 15 bc [2] 0b a1 [2] 09 a0 [2] 12 a6 [2] 0e a1 [2] 12 8e }

  condition:
    any of them
}