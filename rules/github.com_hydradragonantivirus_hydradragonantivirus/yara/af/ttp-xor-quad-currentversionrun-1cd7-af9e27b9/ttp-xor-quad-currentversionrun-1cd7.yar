rule TTP_XOR_QUAD_CurrentVersionRun_1cd7 {
  strings:
    $key_1cd7 = { 4f b8 [2] 6b b6 [2] 40 9a [2] 6e b8 [2] 7a a3 [2] 75 b9 [2] 6b a4 [2] 69 a5 [2] 72 a3 [2] 6e a4 [2] 72 8b }

  condition:
    any of them
}