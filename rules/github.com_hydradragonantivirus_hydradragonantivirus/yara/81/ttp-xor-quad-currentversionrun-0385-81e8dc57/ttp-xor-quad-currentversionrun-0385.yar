rule TTP_XOR_QUAD_CurrentVersionRun_0385 {
  strings:
    $key_0385 = { 50 ea [2] 74 e4 [2] 5f c8 [2] 71 ea [2] 65 f1 [2] 6a eb [2] 74 f6 [2] 76 f7 [2] 6d f1 [2] 71 f6 [2] 6d d9 }

  condition:
    any of them
}