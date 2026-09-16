rule TTP_XOR_QUAD_CurrentVersionRun_3385 {
  strings:
    $key_3385 = { 60 ea [2] 44 e4 [2] 6f c8 [2] 41 ea [2] 55 f1 [2] 5a eb [2] 44 f6 [2] 46 f7 [2] 5d f1 [2] 41 f6 [2] 5d d9 }

  condition:
    any of them
}