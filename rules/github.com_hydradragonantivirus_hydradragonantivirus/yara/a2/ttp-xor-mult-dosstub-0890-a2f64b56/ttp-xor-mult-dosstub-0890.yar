rule TTP_XOR_MULT_DOSStub_0890 {
  strings:
    $key_0890 = { 5c f8 [2] 28 e0 [2] 6f e2 [2] 28 f3 [2] 66 ff [2] 6a f5 [2] 7d fe [2] 66 b0 [2] 5b }

  condition:
    any of them
}