rule TTP_XOR_QUAD_CurrentVersionRun_7f84 {
  strings:
    $key_7f84 = { 2c eb [2] 08 e5 [2] 23 c9 [2] 0d eb [2] 19 f0 [2] 16 ea [2] 08 f7 [2] 0a f6 [2] 11 f0 [2] 0d f7 [2] 11 d8 }

  condition:
    any of them
}