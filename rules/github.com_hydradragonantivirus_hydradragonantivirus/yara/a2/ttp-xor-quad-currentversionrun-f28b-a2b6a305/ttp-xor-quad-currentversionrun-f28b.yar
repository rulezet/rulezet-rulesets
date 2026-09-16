rule TTP_XOR_QUAD_CurrentVersionRun_f28b {
  strings:
    $key_f28b = { a1 e4 [2] 85 ea [2] ae c6 [2] 80 e4 [2] 94 ff [2] 9b e5 [2] 85 f8 [2] 87 f9 [2] 9c ff [2] 80 f8 [2] 9c d7 }

  condition:
    any of them
}