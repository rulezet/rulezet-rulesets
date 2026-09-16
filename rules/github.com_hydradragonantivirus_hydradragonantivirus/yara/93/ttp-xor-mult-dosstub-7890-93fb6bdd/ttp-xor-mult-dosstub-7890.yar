rule TTP_XOR_MULT_DOSStub_7890 {
  strings:
    $key_7890 = { 2c f8 [2] 58 e0 [2] 1f e2 [2] 58 f3 [2] 16 ff [2] 1a f5 [2] 0d fe [2] 16 b0 [2] 2b }

  condition:
    any of them
}