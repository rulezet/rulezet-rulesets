rule TTP_XOR_QUAD_CurrentVersionRun_7f85 {
  strings:
    $key_7f85 = { 2c ea [2] 08 e4 [2] 23 c8 [2] 0d ea [2] 19 f1 [2] 16 eb [2] 08 f6 [2] 0a f7 [2] 11 f1 [2] 0d f6 [2] 11 d9 }

  condition:
    any of them
}