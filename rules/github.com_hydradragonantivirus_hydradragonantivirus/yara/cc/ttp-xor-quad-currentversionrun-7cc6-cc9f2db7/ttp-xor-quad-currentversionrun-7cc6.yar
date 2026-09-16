rule TTP_XOR_QUAD_CurrentVersionRun_7cc6 {
  strings:
    $key_7cc6 = { 2f a9 [2] 0b a7 [2] 20 8b [2] 0e a9 [2] 1a b2 [2] 15 a8 [2] 0b b5 [2] 09 b4 [2] 12 b2 [2] 0e b5 [2] 12 9a }

  condition:
    any of them
}