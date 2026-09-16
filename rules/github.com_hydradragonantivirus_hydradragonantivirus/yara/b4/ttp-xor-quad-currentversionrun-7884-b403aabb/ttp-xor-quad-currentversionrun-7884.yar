rule TTP_XOR_QUAD_CurrentVersionRun_7884 {
  strings:
    $key_7884 = { 2b eb [2] 0f e5 [2] 24 c9 [2] 0a eb [2] 1e f0 [2] 11 ea [2] 0f f7 [2] 0d f6 [2] 16 f0 [2] 0a f7 [2] 16 d8 }

  condition:
    any of them
}