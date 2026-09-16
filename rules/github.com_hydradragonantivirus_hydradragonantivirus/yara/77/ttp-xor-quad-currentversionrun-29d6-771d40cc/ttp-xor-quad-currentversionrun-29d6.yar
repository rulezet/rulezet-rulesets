rule TTP_XOR_QUAD_CurrentVersionRun_29d6 {
  strings:
    $key_29d6 = { 7a b9 [2] 5e b7 [2] 75 9b [2] 5b b9 [2] 4f a2 [2] 40 b8 [2] 5e a5 [2] 5c a4 [2] 47 a2 [2] 5b a5 [2] 47 8a }

  condition:
    any of them
}