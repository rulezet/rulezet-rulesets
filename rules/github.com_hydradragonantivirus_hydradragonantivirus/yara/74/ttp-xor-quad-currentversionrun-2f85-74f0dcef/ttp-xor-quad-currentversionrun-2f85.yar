rule TTP_XOR_QUAD_CurrentVersionRun_2f85 {
  strings:
    $key_2f85 = { 7c ea [2] 58 e4 [2] 73 c8 [2] 5d ea [2] 49 f1 [2] 46 eb [2] 58 f6 [2] 5a f7 [2] 41 f1 [2] 5d f6 [2] 41 d9 }

  condition:
    any of them
}