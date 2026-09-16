rule TTP_XOR_QUAD_CurrentVersionRun_5f8b {
  strings:
    $key_5f8b = { 0c e4 [2] 28 ea [2] 03 c6 [2] 2d e4 [2] 39 ff [2] 36 e5 [2] 28 f8 [2] 2a f9 [2] 31 ff [2] 2d f8 [2] 31 d7 }

  condition:
    any of them
}