rule TTP_XOR_QUAD_CurrentVersionRun_488b {
  strings:
    $key_488b = { 1b e4 [2] 3f ea [2] 14 c6 [2] 3a e4 [2] 2e ff [2] 21 e5 [2] 3f f8 [2] 3d f9 [2] 26 ff [2] 3a f8 [2] 26 d7 }

  condition:
    any of them
}