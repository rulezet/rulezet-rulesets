rule TTP_XOR_QUAD_CurrentVersionRun_f598 {
  strings:
    $key_f598 = { a6 f7 [2] 82 f9 [2] a9 d5 [2] 87 f7 [2] 93 ec [2] 9c f6 [2] 82 eb [2] 80 ea [2] 9b ec [2] 87 eb [2] 9b c4 }

  condition:
    any of them
}