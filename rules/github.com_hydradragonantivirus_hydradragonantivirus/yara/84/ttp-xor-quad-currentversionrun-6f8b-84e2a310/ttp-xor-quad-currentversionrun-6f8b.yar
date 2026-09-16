rule TTP_XOR_QUAD_CurrentVersionRun_6f8b {
  strings:
    $key_6f8b = { 3c e4 [2] 18 ea [2] 33 c6 [2] 1d e4 [2] 09 ff [2] 06 e5 [2] 18 f8 [2] 1a f9 [2] 01 ff [2] 1d f8 [2] 01 d7 }

  condition:
    any of them
}