rule TTP_XOR_QUAD_CurrentVersionRun_3e84 {
  strings:
    $key_3e84 = { 6d eb [2] 49 e5 [2] 62 c9 [2] 4c eb [2] 58 f0 [2] 57 ea [2] 49 f7 [2] 4b f6 [2] 50 f0 [2] 4c f7 [2] 50 d8 }

  condition:
    any of them
}