rule TTP_XOR_QUAD_CurrentVersionRun_078b {
  strings:
    $key_078b = { 54 e4 [2] 70 ea [2] 5b c6 [2] 75 e4 [2] 61 ff [2] 6e e5 [2] 70 f8 [2] 72 f9 [2] 69 ff [2] 75 f8 [2] 69 d7 }

  condition:
    any of them
}