rule TTP_XOR_QUAD_CurrentVersionRun_1dd7 {
  strings:
    $key_1dd7 = { 4e b8 [2] 6a b6 [2] 41 9a [2] 6f b8 [2] 7b a3 [2] 74 b9 [2] 6a a4 [2] 68 a5 [2] 73 a3 [2] 6f a4 [2] 73 8b }

  condition:
    any of them
}