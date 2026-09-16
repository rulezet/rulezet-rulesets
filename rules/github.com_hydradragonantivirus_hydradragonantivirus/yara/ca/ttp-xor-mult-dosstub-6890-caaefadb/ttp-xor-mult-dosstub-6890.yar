rule TTP_XOR_MULT_DOSStub_6890 {
  strings:
    $key_6890 = { 3c f8 [2] 48 e0 [2] 0f e2 [2] 48 f3 [2] 06 ff [2] 0a f5 [2] 1d fe [2] 06 b0 [2] 3b }

  condition:
    any of them
}