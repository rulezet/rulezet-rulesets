rule TTP_XOR_QUAD_CurrentVersionRun_6b8b {
  strings:
    $key_6b8b = { 38 e4 [2] 1c ea [2] 37 c6 [2] 19 e4 [2] 0d ff [2] 02 e5 [2] 1c f8 [2] 1e f9 [2] 05 ff [2] 19 f8 [2] 05 d7 }

  condition:
    any of them
}