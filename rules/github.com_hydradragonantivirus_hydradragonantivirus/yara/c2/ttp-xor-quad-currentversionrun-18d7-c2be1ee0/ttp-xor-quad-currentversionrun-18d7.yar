rule TTP_XOR_QUAD_CurrentVersionRun_18d7 {
  strings:
    $key_18d7 = { 4b b8 [2] 6f b6 [2] 44 9a [2] 6a b8 [2] 7e a3 [2] 71 b9 [2] 6f a4 [2] 6d a5 [2] 76 a3 [2] 6a a4 [2] 76 8b }

  condition:
    any of them
}