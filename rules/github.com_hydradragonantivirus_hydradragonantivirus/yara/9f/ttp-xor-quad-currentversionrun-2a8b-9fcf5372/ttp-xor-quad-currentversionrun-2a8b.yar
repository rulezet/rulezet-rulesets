rule TTP_XOR_QUAD_CurrentVersionRun_2a8b {
  strings:
    $key_2a8b = { 79 e4 [2] 5d ea [2] 76 c6 [2] 58 e4 [2] 4c ff [2] 43 e5 [2] 5d f8 [2] 5f f9 [2] 44 ff [2] 58 f8 [2] 44 d7 }

  condition:
    any of them
}