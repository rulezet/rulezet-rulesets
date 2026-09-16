rule TTP_XOR_QUAD_CurrentVersionRun_19d6 {
  strings:
    $key_19d6 = { 4a b9 [2] 6e b7 [2] 45 9b [2] 6b b9 [2] 7f a2 [2] 70 b8 [2] 6e a5 [2] 6c a4 [2] 77 a2 [2] 6b a5 [2] 77 8a }

  condition:
    any of them
}