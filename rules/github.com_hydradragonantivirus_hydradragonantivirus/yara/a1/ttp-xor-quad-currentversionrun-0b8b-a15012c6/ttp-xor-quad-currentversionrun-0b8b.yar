rule TTP_XOR_QUAD_CurrentVersionRun_0b8b {
  strings:
    $key_0b8b = { 58 e4 [2] 7c ea [2] 57 c6 [2] 79 e4 [2] 6d ff [2] 62 e5 [2] 7c f8 [2] 7e f9 [2] 65 ff [2] 79 f8 [2] 65 d7 }

  condition:
    any of them
}