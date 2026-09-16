rule TTP_XOR_QUAD_CurrentVersionRun_2cd2 {
  strings:
    $key_2cd2 = { 7f bd [2] 5b b3 [2] 70 9f [2] 5e bd [2] 4a a6 [2] 45 bc [2] 5b a1 [2] 59 a0 [2] 42 a6 [2] 5e a1 [2] 42 8e }

  condition:
    any of them
}