rule TTP_XOR_QUAD_CurrentVersionRun_29c7 {
  strings:
    $key_29c7 = { 7a a8 [2] 5e a6 [2] 75 8a [2] 5b a8 [2] 4f b3 [2] 40 a9 [2] 5e b4 [2] 5c b5 [2] 47 b3 [2] 5b b4 [2] 47 9b }

  condition:
    any of them
}