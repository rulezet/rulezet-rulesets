rule TTP_XOR_QUAD_CurrentVersionRun_3a8b {
  strings:
    $key_3a8b = { 69 e4 [2] 4d ea [2] 66 c6 [2] 48 e4 [2] 5c ff [2] 53 e5 [2] 4d f8 [2] 4f f9 [2] 54 ff [2] 48 f8 [2] 54 d7 }

  condition:
    any of them
}