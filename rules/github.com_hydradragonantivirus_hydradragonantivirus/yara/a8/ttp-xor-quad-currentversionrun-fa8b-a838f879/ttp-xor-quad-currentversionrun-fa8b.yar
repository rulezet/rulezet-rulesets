rule TTP_XOR_QUAD_CurrentVersionRun_fa8b {
  strings:
    $key_fa8b = { a9 e4 [2] 8d ea [2] a6 c6 [2] 88 e4 [2] 9c ff [2] 93 e5 [2] 8d f8 [2] 8f f9 [2] 94 ff [2] 88 f8 [2] 94 d7 }

  condition:
    any of them
}