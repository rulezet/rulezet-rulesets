rule TTP_XOR_QUAD_CurrentVersionRun_3cc6 {
  strings:
    $key_3cc6 = { 6f a9 [2] 4b a7 [2] 60 8b [2] 4e a9 [2] 5a b2 [2] 55 a8 [2] 4b b5 [2] 49 b4 [2] 52 b2 [2] 4e b5 [2] 52 9a }

  condition:
    any of them
}