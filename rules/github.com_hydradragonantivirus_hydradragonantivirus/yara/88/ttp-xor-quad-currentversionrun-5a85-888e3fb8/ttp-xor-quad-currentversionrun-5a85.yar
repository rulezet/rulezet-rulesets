rule TTP_XOR_QUAD_CurrentVersionRun_5a85 {
  strings:
    $key_5a85 = { 09 ea [2] 2d e4 [2] 06 c8 [2] 28 ea [2] 3c f1 [2] 33 eb [2] 2d f6 [2] 2f f7 [2] 34 f1 [2] 28 f6 [2] 34 d9 }

  condition:
    any of them
}