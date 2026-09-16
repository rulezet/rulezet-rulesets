rule TTP_XOR_QUAD_CurrentVersionRun_3cd2 {
  strings:
    $key_3cd2 = { 6f bd [2] 4b b3 [2] 60 9f [2] 4e bd [2] 5a a6 [2] 55 bc [2] 4b a1 [2] 49 a0 [2] 52 a6 [2] 4e a1 [2] 52 8e }

  condition:
    any of them
}