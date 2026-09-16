rule TTP_XOR_QUAD_CurrentVersionRun_3e8b {
  strings:
    $key_3e8b = { 6d e4 [2] 49 ea [2] 62 c6 [2] 4c e4 [2] 58 ff [2] 57 e5 [2] 49 f8 [2] 4b f9 [2] 50 ff [2] 4c f8 [2] 50 d7 }

  condition:
    any of them
}