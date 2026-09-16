rule TTP_XOR_QUAD_CurrentVersionRun_09c7 {
  strings:
    $key_09c7 = { 5a a8 [2] 7e a6 [2] 55 8a [2] 7b a8 [2] 6f b3 [2] 60 a9 [2] 7e b4 [2] 7c b5 [2] 67 b3 [2] 7b b4 [2] 67 9b }

  condition:
    any of them
}