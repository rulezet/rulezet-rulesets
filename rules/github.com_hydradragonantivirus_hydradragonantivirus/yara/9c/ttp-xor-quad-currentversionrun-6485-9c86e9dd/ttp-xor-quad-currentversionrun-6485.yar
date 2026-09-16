rule TTP_XOR_QUAD_CurrentVersionRun_6485 {
  strings:
    $key_6485 = { 37 ea [2] 13 e4 [2] 38 c8 [2] 16 ea [2] 02 f1 [2] 0d eb [2] 13 f6 [2] 11 f7 [2] 0a f1 [2] 16 f6 [2] 0a d9 }

  condition:
    any of them
}