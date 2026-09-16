rule TTP_XOR_QUAD_CurrentVersionRun_028b {
  strings:
    $key_028b = { 51 e4 [2] 75 ea [2] 5e c6 [2] 70 e4 [2] 64 ff [2] 6b e5 [2] 75 f8 [2] 77 f9 [2] 6c ff [2] 70 f8 [2] 6c d7 }

  condition:
    any of them
}