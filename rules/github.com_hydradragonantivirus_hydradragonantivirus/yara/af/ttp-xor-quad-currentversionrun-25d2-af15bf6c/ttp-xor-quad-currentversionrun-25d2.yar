rule TTP_XOR_QUAD_CurrentVersionRun_25d2 {
  strings:
    $key_25d2 = { 76 bd [2] 52 b3 [2] 79 9f [2] 57 bd [2] 43 a6 [2] 4c bc [2] 52 a1 [2] 50 a0 [2] 4b a6 [2] 57 a1 [2] 4b 8e }

  condition:
    any of them
}