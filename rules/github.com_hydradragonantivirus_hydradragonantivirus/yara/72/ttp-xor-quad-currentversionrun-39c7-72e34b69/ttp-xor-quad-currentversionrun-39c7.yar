rule TTP_XOR_QUAD_CurrentVersionRun_39c7 {
  strings:
    $key_39c7 = { 6a a8 [2] 4e a6 [2] 65 8a [2] 4b a8 [2] 5f b3 [2] 50 a9 [2] 4e b4 [2] 4c b5 [2] 57 b3 [2] 4b b4 [2] 57 9b }

  condition:
    any of them
}