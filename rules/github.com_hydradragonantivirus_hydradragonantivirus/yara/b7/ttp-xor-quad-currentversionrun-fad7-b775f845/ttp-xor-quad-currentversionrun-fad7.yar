rule TTP_XOR_QUAD_CurrentVersionRun_fad7 {
  strings:
    $key_fad7 = { a9 b8 [2] 8d b6 [2] a6 9a [2] 88 b8 [2] 9c a3 [2] 93 b9 [2] 8d a4 [2] 8f a5 [2] 94 a3 [2] 88 a4 [2] 94 8b }

  condition:
    any of them
}