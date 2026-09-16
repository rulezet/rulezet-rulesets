rule TTP_XOR_QUAD_CurrentVersionRun_1dc7 {
  strings:
    $key_1dc7 = { 4e a8 [2] 6a a6 [2] 41 8a [2] 6f a8 [2] 7b b3 [2] 74 a9 [2] 6a b4 [2] 68 b5 [2] 73 b3 [2] 6f b4 [2] 73 9b }

  condition:
    any of them
}