rule TTP_XOR_QUAD_CurrentVersionRun_f08b {
  strings:
    $key_f08b = { a3 e4 [2] 87 ea [2] ac c6 [2] 82 e4 [2] 96 ff [2] 99 e5 [2] 87 f8 [2] 85 f9 [2] 9e ff [2] 82 f8 [2] 9e d7 }

  condition:
    any of them
}