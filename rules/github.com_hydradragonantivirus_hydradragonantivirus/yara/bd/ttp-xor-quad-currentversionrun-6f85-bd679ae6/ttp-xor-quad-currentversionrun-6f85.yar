rule TTP_XOR_QUAD_CurrentVersionRun_6f85 {
  strings:
    $key_6f85 = { 3c ea [2] 18 e4 [2] 33 c8 [2] 1d ea [2] 09 f1 [2] 06 eb [2] 18 f6 [2] 1a f7 [2] 01 f1 [2] 1d f6 [2] 01 d9 }

  condition:
    any of them
}