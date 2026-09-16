rule TTP_XOR_QUAD_CurrentVersionRun_e28b {
  strings:
    $key_e28b = { b1 e4 [2] 95 ea [2] be c6 [2] 90 e4 [2] 84 ff [2] 8b e5 [2] 95 f8 [2] 97 f9 [2] 8c ff [2] 90 f8 [2] 8c d7 }

  condition:
    any of them
}