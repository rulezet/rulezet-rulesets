rule TTP_XOR_QUAD_CurrentVersionRun_4cd6 {
  strings:
    $key_4cd6 = { 1f b9 [2] 3b b7 [2] 10 9b [2] 3e b9 [2] 2a a2 [2] 25 b8 [2] 3b a5 [2] 39 a4 [2] 22 a2 [2] 3e a5 [2] 22 8a }

  condition:
    any of them
}