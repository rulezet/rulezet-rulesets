rule TTP_XOR_QUAD_CurrentVersionRun_448b {
  strings:
    $key_448b = { 17 e4 [2] 33 ea [2] 18 c6 [2] 36 e4 [2] 22 ff [2] 2d e5 [2] 33 f8 [2] 31 f9 [2] 2a ff [2] 36 f8 [2] 2a d7 }

  condition:
    any of them
}