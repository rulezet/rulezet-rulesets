rule TTP_XOR_QUAD_CurrentVersionRun_2385 {
  strings:
    $key_2385 = { 70 ea [2] 54 e4 [2] 7f c8 [2] 51 ea [2] 45 f1 [2] 4a eb [2] 54 f6 [2] 56 f7 [2] 4d f1 [2] 51 f6 [2] 4d d9 }

  condition:
    any of them
}