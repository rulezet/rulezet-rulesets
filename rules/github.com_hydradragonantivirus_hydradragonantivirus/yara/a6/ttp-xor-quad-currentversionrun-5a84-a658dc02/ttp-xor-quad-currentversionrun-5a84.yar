rule TTP_XOR_QUAD_CurrentVersionRun_5a84 {
  strings:
    $key_5a84 = { 09 eb [2] 2d e5 [2] 06 c9 [2] 28 eb [2] 3c f0 [2] 33 ea [2] 2d f7 [2] 2f f6 [2] 34 f0 [2] 28 f7 [2] 34 d8 }

  condition:
    any of them
}