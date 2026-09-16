rule TTP_XOR_MULT_DOSStub_5890 {
  strings:
    $key_5890 = { 0c f8 [2] 78 e0 [2] 3f e2 [2] 78 f3 [2] 36 ff [2] 3a f5 [2] 2d fe [2] 36 b0 [2] 0b }

  condition:
    any of them
}