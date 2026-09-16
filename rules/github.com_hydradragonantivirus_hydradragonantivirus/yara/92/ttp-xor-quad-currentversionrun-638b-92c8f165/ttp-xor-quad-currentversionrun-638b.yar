rule TTP_XOR_QUAD_CurrentVersionRun_638b {
  strings:
    $key_638b = { 30 e4 [2] 14 ea [2] 3f c6 [2] 11 e4 [2] 05 ff [2] 0a e5 [2] 14 f8 [2] 16 f9 [2] 0d ff [2] 11 f8 [2] 0d d7 }

  condition:
    any of them
}