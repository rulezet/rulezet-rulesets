rule TTP_XOR_QUAD_CurrentVersionRun_7cc7 {
  strings:
    $key_7cc7 = { 2f a8 [2] 0b a6 [2] 20 8a [2] 0e a8 [2] 1a b3 [2] 15 a9 [2] 0b b4 [2] 09 b5 [2] 12 b3 [2] 0e b4 [2] 12 9b }

  condition:
    any of them
}