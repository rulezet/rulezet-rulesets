rule TTP_XOR_QUAD_CurrentVersionRun_0cc6 {
  strings:
    $key_0cc6 = { 5f a9 [2] 7b a7 [2] 50 8b [2] 7e a9 [2] 6a b2 [2] 65 a8 [2] 7b b5 [2] 79 b4 [2] 62 b2 [2] 7e b5 [2] 62 9a }

  condition:
    any of them
}