rule TTP_XOR_QUAD_CurrentVersionRun_fb84 {
  strings:
    $key_fb84 = { a8 eb [2] 8c e5 [2] a7 c9 [2] 89 eb [2] 9d f0 [2] 92 ea [2] 8c f7 [2] 8e f6 [2] 95 f0 [2] 89 f7 [2] 95 d8 }

  condition:
    any of them
}