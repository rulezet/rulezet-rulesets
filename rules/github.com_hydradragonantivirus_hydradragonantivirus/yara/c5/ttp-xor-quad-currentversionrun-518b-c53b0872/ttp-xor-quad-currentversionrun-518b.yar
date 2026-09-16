rule TTP_XOR_QUAD_CurrentVersionRun_518b {
  strings:
    $key_518b = { 02 e4 [2] 26 ea [2] 0d c6 [2] 23 e4 [2] 37 ff [2] 38 e5 [2] 26 f8 [2] 24 f9 [2] 3f ff [2] 23 f8 [2] 3f d7 }

  condition:
    any of them
}