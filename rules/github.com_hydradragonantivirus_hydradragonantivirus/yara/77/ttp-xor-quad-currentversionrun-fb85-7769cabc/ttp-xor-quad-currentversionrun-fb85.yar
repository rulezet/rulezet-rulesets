rule TTP_XOR_QUAD_CurrentVersionRun_fb85 {
  strings:
    $key_fb85 = { a8 ea [2] 8c e4 [2] a7 c8 [2] 89 ea [2] 9d f1 [2] 92 eb [2] 8c f6 [2] 8e f7 [2] 95 f1 [2] 89 f6 [2] 95 d9 }

  condition:
    any of them
}