rule TTP_XOR_QUAD_CurrentVersionRun_5f85 {
  strings:
    $key_5f85 = { 0c ea [2] 28 e4 [2] 03 c8 [2] 2d ea [2] 39 f1 [2] 36 eb [2] 28 f6 [2] 2a f7 [2] 31 f1 [2] 2d f6 [2] 31 d9 }

  condition:
    any of them
}