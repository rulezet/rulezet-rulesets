rule TTP_XOR_QUAD_CurrentVersionRun_7dd7 {
  strings:
    $key_7dd7 = { 2e b8 [2] 0a b6 [2] 21 9a [2] 0f b8 [2] 1b a3 [2] 14 b9 [2] 0a a4 [2] 08 a5 [2] 13 a3 [2] 0f a4 [2] 13 8b }

  condition:
    any of them
}