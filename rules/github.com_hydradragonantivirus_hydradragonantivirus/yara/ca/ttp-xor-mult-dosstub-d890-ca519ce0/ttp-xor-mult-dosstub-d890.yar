rule TTP_XOR_MULT_DOSStub_d890 {
  strings:
    $key_d890 = { 8c f8 [2] f8 e0 [2] bf e2 [2] f8 f3 [2] b6 ff [2] ba f5 [2] ad fe [2] b6 b0 [2] 8b }

  condition:
    any of them
}