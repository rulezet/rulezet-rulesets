rule TTP_XOR_QUAD_CurrentVersionRun_4585 {
  strings:
    $key_4585 = { 16 ea [2] 32 e4 [2] 19 c8 [2] 37 ea [2] 23 f1 [2] 2c eb [2] 32 f6 [2] 30 f7 [2] 2b f1 [2] 37 f6 [2] 2b d9 }

  condition:
    any of them
}