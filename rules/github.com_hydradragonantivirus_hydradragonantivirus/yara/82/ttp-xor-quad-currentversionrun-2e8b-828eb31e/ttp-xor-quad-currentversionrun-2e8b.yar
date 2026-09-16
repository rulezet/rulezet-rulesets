rule TTP_XOR_QUAD_CurrentVersionRun_2e8b {
  strings:
    $key_2e8b = { 7d e4 [2] 59 ea [2] 72 c6 [2] 5c e4 [2] 48 ff [2] 47 e5 [2] 59 f8 [2] 5b f9 [2] 40 ff [2] 5c f8 [2] 40 d7 }

  condition:
    any of them
}