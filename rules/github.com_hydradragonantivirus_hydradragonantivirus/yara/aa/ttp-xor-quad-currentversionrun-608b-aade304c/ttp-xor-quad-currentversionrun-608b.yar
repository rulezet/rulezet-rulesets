rule TTP_XOR_QUAD_CurrentVersionRun_608b {
  strings:
    $key_608b = { 33 e4 [2] 17 ea [2] 3c c6 [2] 12 e4 [2] 06 ff [2] 09 e5 [2] 17 f8 [2] 15 f9 [2] 0e ff [2] 12 f8 [2] 0e d7 }

  condition:
    any of them
}