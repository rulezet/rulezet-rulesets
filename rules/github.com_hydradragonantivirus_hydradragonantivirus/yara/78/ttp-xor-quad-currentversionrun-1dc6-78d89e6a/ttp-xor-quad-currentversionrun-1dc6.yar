rule TTP_XOR_QUAD_CurrentVersionRun_1dc6 {
  strings:
    $key_1dc6 = { 4e a9 [2] 6a a7 [2] 41 8b [2] 6f a9 [2] 7b b2 [2] 74 a8 [2] 6a b5 [2] 68 b4 [2] 73 b2 [2] 6f b5 [2] 73 9a }

  condition:
    any of them
}