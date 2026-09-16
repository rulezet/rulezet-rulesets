rule TTP_XOR_QUAD_CurrentVersionRun_5e84 {
  strings:
    $key_5e84 = { 0d eb [2] 29 e5 [2] 02 c9 [2] 2c eb [2] 38 f0 [2] 37 ea [2] 29 f7 [2] 2b f6 [2] 30 f0 [2] 2c f7 [2] 30 d8 }

  condition:
    any of them
}