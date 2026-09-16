rule TTP_XOR_QUAD_CurrentVersionRun_1e85 {
  strings:
    $key_1e85 = { 4d ea [2] 69 e4 [2] 42 c8 [2] 6c ea [2] 78 f1 [2] 77 eb [2] 69 f6 [2] 6b f7 [2] 70 f1 [2] 6c f6 [2] 70 d9 }

  condition:
    any of them
}