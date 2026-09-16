rule TTP_XOR_QUAD_CurrentVersionRun_78d2 {
  strings:
    $key_78d2 = { 2b bd [2] 0f b3 [2] 24 9f [2] 0a bd [2] 1e a6 [2] 11 bc [2] 0f a1 [2] 0d a0 [2] 16 a6 [2] 0a a1 [2] 16 8e }

  condition:
    any of them
}