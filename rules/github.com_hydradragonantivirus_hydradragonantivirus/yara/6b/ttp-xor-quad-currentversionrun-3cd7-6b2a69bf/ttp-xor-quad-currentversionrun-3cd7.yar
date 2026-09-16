rule TTP_XOR_QUAD_CurrentVersionRun_3cd7 {
  strings:
    $key_3cd7 = { 6f b8 [2] 4b b6 [2] 60 9a [2] 4e b8 [2] 5a a3 [2] 55 b9 [2] 4b a4 [2] 49 a5 [2] 52 a3 [2] 4e a4 [2] 52 8b }

  condition:
    any of them
}