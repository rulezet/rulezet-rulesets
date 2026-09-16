rule TTP_XOR_QUAD_CurrentVersionRun_6f84 {
  strings:
    $key_6f84 = { 3c eb [2] 18 e5 [2] 33 c9 [2] 1d eb [2] 09 f0 [2] 06 ea [2] 18 f7 [2] 1a f6 [2] 01 f0 [2] 1d f7 [2] 01 d8 }

  condition:
    any of them
}