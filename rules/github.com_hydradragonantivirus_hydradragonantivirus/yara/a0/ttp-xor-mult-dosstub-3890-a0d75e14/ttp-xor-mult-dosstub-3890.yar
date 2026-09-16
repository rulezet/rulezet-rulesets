rule TTP_XOR_MULT_DOSStub_3890 {
  strings:
    $key_3890 = { 6c f8 [2] 18 e0 [2] 5f e2 [2] 18 f3 [2] 56 ff [2] 5a f5 [2] 4d fe [2] 56 b0 [2] 6b }

  condition:
    any of them
}