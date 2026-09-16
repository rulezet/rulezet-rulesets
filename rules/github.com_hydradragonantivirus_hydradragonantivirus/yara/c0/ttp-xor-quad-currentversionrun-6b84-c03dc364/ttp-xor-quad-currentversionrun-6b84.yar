rule TTP_XOR_QUAD_CurrentVersionRun_6b84 {
  strings:
    $key_6b84 = { 38 eb [2] 1c e5 [2] 37 c9 [2] 19 eb [2] 0d f0 [2] 02 ea [2] 1c f7 [2] 1e f6 [2] 05 f0 [2] 19 f7 [2] 05 d8 }

  condition:
    any of them
}