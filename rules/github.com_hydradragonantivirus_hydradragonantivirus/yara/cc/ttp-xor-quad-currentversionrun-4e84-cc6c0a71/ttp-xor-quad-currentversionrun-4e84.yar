rule TTP_XOR_QUAD_CurrentVersionRun_4e84 {
  strings:
    $key_4e84 = { 1d eb [2] 39 e5 [2] 12 c9 [2] 3c eb [2] 28 f0 [2] 27 ea [2] 39 f7 [2] 3b f6 [2] 20 f0 [2] 3c f7 [2] 20 d8 }

  condition:
    any of them
}