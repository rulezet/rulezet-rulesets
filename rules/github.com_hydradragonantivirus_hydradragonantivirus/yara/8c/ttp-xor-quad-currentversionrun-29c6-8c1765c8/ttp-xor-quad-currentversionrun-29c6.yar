rule TTP_XOR_QUAD_CurrentVersionRun_29c6 {
  strings:
    $key_29c6 = { 7a a9 [2] 5e a7 [2] 75 8b [2] 5b a9 [2] 4f b2 [2] 40 a8 [2] 5e b5 [2] 5c b4 [2] 47 b2 [2] 5b b5 [2] 47 9a }

  condition:
    any of them
}