rule TTP_XOR_QUAD_CurrentVersionRun_588b {
  strings:
    $key_588b = { 0b e4 [2] 2f ea [2] 04 c6 [2] 2a e4 [2] 3e ff [2] 31 e5 [2] 2f f8 [2] 2d f9 [2] 36 ff [2] 2a f8 [2] 36 d7 }

  condition:
    any of them
}