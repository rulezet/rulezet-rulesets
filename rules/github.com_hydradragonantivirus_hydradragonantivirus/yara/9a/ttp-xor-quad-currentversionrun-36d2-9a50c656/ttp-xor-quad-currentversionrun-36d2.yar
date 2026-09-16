rule TTP_XOR_QUAD_CurrentVersionRun_36d2 {
  strings:
    $key_36d2 = { 65 bd [2] 41 b3 [2] 6a 9f [2] 44 bd [2] 50 a6 [2] 5f bc [2] 41 a1 [2] 43 a0 [2] 58 a6 [2] 44 a1 [2] 58 8e }

  condition:
    any of them
}