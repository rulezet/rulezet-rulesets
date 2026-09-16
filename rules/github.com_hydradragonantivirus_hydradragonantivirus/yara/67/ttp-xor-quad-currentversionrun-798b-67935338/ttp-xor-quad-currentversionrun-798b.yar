rule TTP_XOR_QUAD_CurrentVersionRun_798b {
  strings:
    $key_798b = { 2a e4 [2] 0e ea [2] 25 c6 [2] 0b e4 [2] 1f ff [2] 10 e5 [2] 0e f8 [2] 0c f9 [2] 17 ff [2] 0b f8 [2] 17 d7 }

  condition:
    any of them
}