rule TTP_XOR_QUAD_CurrentVersionRun_1f85 {
  strings:
    $key_1f85 = { 4c ea [2] 68 e4 [2] 43 c8 [2] 6d ea [2] 79 f1 [2] 76 eb [2] 68 f6 [2] 6a f7 [2] 71 f1 [2] 6d f6 [2] 71 d9 }

  condition:
    any of them
}