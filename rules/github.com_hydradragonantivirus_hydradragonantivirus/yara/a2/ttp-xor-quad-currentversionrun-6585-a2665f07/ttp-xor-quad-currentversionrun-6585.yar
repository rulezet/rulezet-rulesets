rule TTP_XOR_QUAD_CurrentVersionRun_6585 {
  strings:
    $key_6585 = { 36 ea [2] 12 e4 [2] 39 c8 [2] 17 ea [2] 03 f1 [2] 0c eb [2] 12 f6 [2] 10 f7 [2] 0b f1 [2] 17 f6 [2] 0b d9 }

  condition:
    any of them
}