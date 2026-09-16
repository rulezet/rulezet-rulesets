rule TTP_XOR_QUAD_CurrentVersionRun_19c7 {
  strings:
    $key_19c7 = { 4a a8 [2] 6e a6 [2] 45 8a [2] 6b a8 [2] 7f b3 [2] 70 a9 [2] 6e b4 [2] 6c b5 [2] 77 b3 [2] 6b b4 [2] 77 9b }

  condition:
    any of them
}