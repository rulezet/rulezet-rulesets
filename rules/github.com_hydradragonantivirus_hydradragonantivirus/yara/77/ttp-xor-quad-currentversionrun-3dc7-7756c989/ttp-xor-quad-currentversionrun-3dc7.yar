rule TTP_XOR_QUAD_CurrentVersionRun_3dc7 {
  strings:
    $key_3dc7 = { 6e a8 [2] 4a a6 [2] 61 8a [2] 4f a8 [2] 5b b3 [2] 54 a9 [2] 4a b4 [2] 48 b5 [2] 53 b3 [2] 4f b4 [2] 53 9b }

  condition:
    any of them
}