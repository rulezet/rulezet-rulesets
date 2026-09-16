rule TTP_XOR_QUAD_CurrentVersionRun_468b {
  strings:
    $key_468b = { 15 e4 [2] 31 ea [2] 1a c6 [2] 34 e4 [2] 20 ff [2] 2f e5 [2] 31 f8 [2] 33 f9 [2] 28 ff [2] 34 f8 [2] 28 d7 }

  condition:
    any of them
}