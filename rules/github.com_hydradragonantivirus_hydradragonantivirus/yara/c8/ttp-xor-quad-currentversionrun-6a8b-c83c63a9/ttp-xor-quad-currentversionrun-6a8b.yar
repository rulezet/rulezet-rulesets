rule TTP_XOR_QUAD_CurrentVersionRun_6a8b {
  strings:
    $key_6a8b = { 39 e4 [2] 1d ea [2] 36 c6 [2] 18 e4 [2] 0c ff [2] 03 e5 [2] 1d f8 [2] 1f f9 [2] 04 ff [2] 18 f8 [2] 04 d7 }

  condition:
    any of them
}