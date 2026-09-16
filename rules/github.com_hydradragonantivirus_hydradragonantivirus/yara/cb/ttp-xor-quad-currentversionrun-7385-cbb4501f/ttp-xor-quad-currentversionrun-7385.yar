rule TTP_XOR_QUAD_CurrentVersionRun_7385 {
  strings:
    $key_7385 = { 20 ea [2] 04 e4 [2] 2f c8 [2] 01 ea [2] 15 f1 [2] 1a eb [2] 04 f6 [2] 06 f7 [2] 1d f1 [2] 01 f6 [2] 1d d9 }

  condition:
    any of them
}