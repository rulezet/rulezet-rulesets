rule TTP_XOR_QUAD_CurrentVersionRun_4e8b {
  strings:
    $key_4e8b = { 1d e4 [2] 39 ea [2] 12 c6 [2] 3c e4 [2] 28 ff [2] 27 e5 [2] 39 f8 [2] 3b f9 [2] 20 ff [2] 3c f8 [2] 20 d7 }

  condition:
    any of them
}