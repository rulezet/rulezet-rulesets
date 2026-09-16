rule TTP_XOR_QUAD_CurrentVersionRun_188b {
  strings:
    $key_188b = { 4b e4 [2] 6f ea [2] 44 c6 [2] 6a e4 [2] 7e ff [2] 71 e5 [2] 6f f8 [2] 6d f9 [2] 76 ff [2] 6a f8 [2] 76 d7 }

  condition:
    any of them
}