rule TTP_XOR_QUAD_CurrentVersionRun_108b {
  strings:
    $key_108b = { 43 e4 [2] 67 ea [2] 4c c6 [2] 62 e4 [2] 76 ff [2] 79 e5 [2] 67 f8 [2] 65 f9 [2] 7e ff [2] 62 f8 [2] 7e d7 }

  condition:
    any of them
}