rule TTP_XOR_QUAD_CurrentVersionRun_708b {
  strings:
    $key_708b = { 23 e4 [2] 07 ea [2] 2c c6 [2] 02 e4 [2] 16 ff [2] 19 e5 [2] 07 f8 [2] 05 f9 [2] 1e ff [2] 02 f8 [2] 1e d7 }

  condition:
    any of them
}