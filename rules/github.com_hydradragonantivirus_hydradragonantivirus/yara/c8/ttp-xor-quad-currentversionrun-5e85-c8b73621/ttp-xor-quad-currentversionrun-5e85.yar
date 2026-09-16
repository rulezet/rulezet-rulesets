rule TTP_XOR_QUAD_CurrentVersionRun_5e85 {
  strings:
    $key_5e85 = { 0d ea [2] 29 e4 [2] 02 c8 [2] 2c ea [2] 38 f1 [2] 37 eb [2] 29 f6 [2] 2b f7 [2] 30 f1 [2] 2c f6 [2] 30 d9 }

  condition:
    any of them
}