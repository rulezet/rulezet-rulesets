rule TTP_XOR_QUAD_CurrentVersionRun_128b {
  strings:
    $key_128b = { 41 e4 [2] 65 ea [2] 4e c6 [2] 60 e4 [2] 74 ff [2] 7b e5 [2] 65 f8 [2] 67 f9 [2] 7c ff [2] 60 f8 [2] 7c d7 }

  condition:
    any of them
}