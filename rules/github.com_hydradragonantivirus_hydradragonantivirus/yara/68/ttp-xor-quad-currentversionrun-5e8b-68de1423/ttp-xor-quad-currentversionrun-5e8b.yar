rule TTP_XOR_QUAD_CurrentVersionRun_5e8b {
  strings:
    $key_5e8b = { 0d e4 [2] 29 ea [2] 02 c6 [2] 2c e4 [2] 38 ff [2] 37 e5 [2] 29 f8 [2] 2b f9 [2] 30 ff [2] 2c f8 [2] 30 d7 }

  condition:
    any of them
}