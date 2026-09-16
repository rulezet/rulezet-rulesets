rule TTP_XOR_QUAD_CurrentVersionRun_0f8b {
  strings:
    $key_0f8b = { 5c e4 [2] 78 ea [2] 53 c6 [2] 7d e4 [2] 69 ff [2] 66 e5 [2] 78 f8 [2] 7a f9 [2] 61 ff [2] 7d f8 [2] 61 d7 }

  condition:
    any of them
}