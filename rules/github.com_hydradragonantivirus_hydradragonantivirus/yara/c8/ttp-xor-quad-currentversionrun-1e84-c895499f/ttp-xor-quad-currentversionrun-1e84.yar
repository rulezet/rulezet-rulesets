rule TTP_XOR_QUAD_CurrentVersionRun_1e84 {
  strings:
    $key_1e84 = { 4d eb [2] 69 e5 [2] 42 c9 [2] 6c eb [2] 78 f0 [2] 77 ea [2] 69 f7 [2] 6b f6 [2] 70 f0 [2] 6c f7 [2] 70 d8 }

  condition:
    any of them
}