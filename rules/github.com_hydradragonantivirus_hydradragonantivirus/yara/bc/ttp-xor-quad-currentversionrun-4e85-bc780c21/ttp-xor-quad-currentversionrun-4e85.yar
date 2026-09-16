rule TTP_XOR_QUAD_CurrentVersionRun_4e85 {
  strings:
    $key_4e85 = { 1d ea [2] 39 e4 [2] 12 c8 [2] 3c ea [2] 28 f1 [2] 27 eb [2] 39 f6 [2] 3b f7 [2] 20 f1 [2] 3c f6 [2] 20 d9 }

  condition:
    any of them
}