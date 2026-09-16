rule TTP_XOR_QUAD_CurrentVersionRun_6385 {
  strings:
    $key_6385 = { 30 ea [2] 14 e4 [2] 3f c8 [2] 11 ea [2] 05 f1 [2] 0a eb [2] 14 f6 [2] 16 f7 [2] 0d f1 [2] 11 f6 [2] 0d d9 }

  condition:
    any of them
}