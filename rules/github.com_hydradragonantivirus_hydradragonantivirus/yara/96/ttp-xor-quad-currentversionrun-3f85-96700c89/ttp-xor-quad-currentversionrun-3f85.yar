rule TTP_XOR_QUAD_CurrentVersionRun_3f85 {
  strings:
    $key_3f85 = { 6c ea [2] 48 e4 [2] 63 c8 [2] 4d ea [2] 59 f1 [2] 56 eb [2] 48 f6 [2] 4a f7 [2] 51 f1 [2] 4d f6 [2] 51 d9 }

  condition:
    any of them
}