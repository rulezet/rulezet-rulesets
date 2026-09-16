rule TTP_XOR_QUAD_CurrentVersionRun_58d7 {
  strings:
    $key_58d7 = { 0b b8 [2] 2f b6 [2] 04 9a [2] 2a b8 [2] 3e a3 [2] 31 b9 [2] 2f a4 [2] 2d a5 [2] 36 a3 [2] 2a a4 [2] 36 8b }

  condition:
    any of them
}