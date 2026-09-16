rule TTP_XOR_QUAD_CurrentVersionRun_4299 {
  strings:
    $key_4299 = { 11 f6 [2] 35 f8 [2] 1e d4 [2] 30 f6 [2] 24 ed [2] 2b f7 [2] 35 ea [2] 37 eb [2] 2c ed [2] 30 ea [2] 2c c5 }

  condition:
    any of them
}