rule TTP_XOR_QUAD_CurrentVersionRun_308b {
  strings:
    $key_308b = { 63 e4 [2] 47 ea [2] 6c c6 [2] 42 e4 [2] 56 ff [2] 59 e5 [2] 47 f8 [2] 45 f9 [2] 5e ff [2] 42 f8 [2] 5e d7 }

  condition:
    any of them
}