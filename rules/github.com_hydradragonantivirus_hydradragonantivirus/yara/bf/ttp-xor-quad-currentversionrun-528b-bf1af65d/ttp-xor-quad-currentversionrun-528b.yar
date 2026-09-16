rule TTP_XOR_QUAD_CurrentVersionRun_528b {
  strings:
    $key_528b = { 01 e4 [2] 25 ea [2] 0e c6 [2] 20 e4 [2] 34 ff [2] 3b e5 [2] 25 f8 [2] 27 f9 [2] 3c ff [2] 20 f8 [2] 3c d7 }

  condition:
    any of them
}