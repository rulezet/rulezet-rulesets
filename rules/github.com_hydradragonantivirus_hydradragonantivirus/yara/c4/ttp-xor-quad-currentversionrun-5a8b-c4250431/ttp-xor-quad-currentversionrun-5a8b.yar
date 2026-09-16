rule TTP_XOR_QUAD_CurrentVersionRun_5a8b {
  strings:
    $key_5a8b = { 09 e4 [2] 2d ea [2] 06 c6 [2] 28 e4 [2] 3c ff [2] 33 e5 [2] 2d f8 [2] 2f f9 [2] 34 ff [2] 28 f8 [2] 34 d7 }

  condition:
    any of them
}