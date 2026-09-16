rule TTP_XOR_QUAD_CurrentVersionRun_7485 {
  strings:
    $key_7485 = { 27 ea [2] 03 e4 [2] 28 c8 [2] 06 ea [2] 12 f1 [2] 1d eb [2] 03 f6 [2] 01 f7 [2] 1a f1 [2] 06 f6 [2] 1a d9 }

  condition:
    any of them
}