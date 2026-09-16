rule TTP_XOR_QUAD_CurrentVersionRun_4385 {
  strings:
    $key_4385 = { 10 ea [2] 34 e4 [2] 1f c8 [2] 31 ea [2] 25 f1 [2] 2a eb [2] 34 f6 [2] 36 f7 [2] 2d f1 [2] 31 f6 [2] 2d d9 }

  condition:
    any of them
}