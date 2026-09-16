rule TTP_XOR_QUAD_CurrentVersionRun_228b {
  strings:
    $key_228b = { 71 e4 [2] 55 ea [2] 7e c6 [2] 50 e4 [2] 44 ff [2] 4b e5 [2] 55 f8 [2] 57 f9 [2] 4c ff [2] 50 f8 [2] 4c d7 }

  condition:
    any of them
}