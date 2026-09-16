rule TTP_XOR_QUAD_CurrentVersionRun_e78b {
  strings:
    $key_e78b = { b4 e4 [2] 90 ea [2] bb c6 [2] 95 e4 [2] 81 ff [2] 8e e5 [2] 90 f8 [2] 92 f9 [2] 89 ff [2] 95 f8 [2] 89 d7 }

  condition:
    any of them
}