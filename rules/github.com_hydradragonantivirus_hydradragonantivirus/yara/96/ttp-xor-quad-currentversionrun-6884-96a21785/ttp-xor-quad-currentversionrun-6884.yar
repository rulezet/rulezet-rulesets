rule TTP_XOR_QUAD_CurrentVersionRun_6884 {
  strings:
    $key_6884 = { 3b eb [2] 1f e5 [2] 34 c9 [2] 1a eb [2] 0e f0 [2] 01 ea [2] 1f f7 [2] 1d f6 [2] 06 f0 [2] 1a f7 [2] 06 d8 }

  condition:
    any of them
}