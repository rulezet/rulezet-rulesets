rule TTP_XOR_QUAD_CurrentVersionRun_28d7 {
  strings:
    $key_28d7 = { 7b b8 [2] 5f b6 [2] 74 9a [2] 5a b8 [2] 4e a3 [2] 41 b9 [2] 5f a4 [2] 5d a5 [2] 46 a3 [2] 5a a4 [2] 46 8b }

  condition:
    any of them
}