rule TTP_XOR_QUAD_CurrentVersionRun_6cc7 {
  strings:
    $key_6cc7 = { 3f a8 [2] 1b a6 [2] 30 8a [2] 1e a8 [2] 0a b3 [2] 05 a9 [2] 1b b4 [2] 19 b5 [2] 02 b3 [2] 1e b4 [2] 02 9b }

  condition:
    any of them
}