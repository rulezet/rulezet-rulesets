rule TTP_XOR_QUAD_CurrentVersionRun_1b84 {
  strings:
    $key_1b84 = { 48 eb [2] 6c e5 [2] 47 c9 [2] 69 eb [2] 7d f0 [2] 72 ea [2] 6c f7 [2] 6e f6 [2] 75 f0 [2] 69 f7 [2] 75 d8 }

  condition:
    any of them
}