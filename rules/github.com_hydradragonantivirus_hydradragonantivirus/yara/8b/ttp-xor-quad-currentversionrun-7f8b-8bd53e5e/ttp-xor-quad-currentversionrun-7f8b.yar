rule TTP_XOR_QUAD_CurrentVersionRun_7f8b {
  strings:
    $key_7f8b = { 2c e4 [2] 08 ea [2] 23 c6 [2] 0d e4 [2] 19 ff [2] 16 e5 [2] 08 f8 [2] 0a f9 [2] 11 ff [2] 0d f8 [2] 11 d7 }

  condition:
    any of them
}