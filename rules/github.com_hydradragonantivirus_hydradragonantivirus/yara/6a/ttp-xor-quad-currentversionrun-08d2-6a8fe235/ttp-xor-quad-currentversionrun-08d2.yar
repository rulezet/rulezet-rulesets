rule TTP_XOR_QUAD_CurrentVersionRun_08d2 {
  strings:
    $key_08d2 = { 5b bd [2] 7f b3 [2] 54 9f [2] 7a bd [2] 6e a6 [2] 61 bc [2] 7f a1 [2] 7d a0 [2] 66 a6 [2] 7a a1 [2] 66 8e }

  condition:
    any of them
}