rule TTP_XOR_QUAD_CurrentVersionRun_5884 {
  strings:
    $key_5884 = { 0b eb [2] 2f e5 [2] 04 c9 [2] 2a eb [2] 3e f0 [2] 31 ea [2] 2f f7 [2] 2d f6 [2] 36 f0 [2] 2a f7 [2] 36 d8 }

  condition:
    any of them
}