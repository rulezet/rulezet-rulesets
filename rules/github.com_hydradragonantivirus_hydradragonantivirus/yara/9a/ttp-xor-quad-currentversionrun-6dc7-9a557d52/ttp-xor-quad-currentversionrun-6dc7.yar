rule TTP_XOR_QUAD_CurrentVersionRun_6dc7 {
  strings:
    $key_6dc7 = { 3e a8 [2] 1a a6 [2] 31 8a [2] 1f a8 [2] 0b b3 [2] 04 a9 [2] 1a b4 [2] 18 b5 [2] 03 b3 [2] 1f b4 [2] 03 9b }

  condition:
    any of them
}