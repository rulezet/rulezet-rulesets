rule TTP_XOR_QUAD_CurrentVersionRun_58d2 {
  strings:
    $key_58d2 = { 0b bd [2] 2f b3 [2] 04 9f [2] 2a bd [2] 3e a6 [2] 31 bc [2] 2f a1 [2] 2d a0 [2] 36 a6 [2] 2a a1 [2] 36 8e }

  condition:
    any of them
}