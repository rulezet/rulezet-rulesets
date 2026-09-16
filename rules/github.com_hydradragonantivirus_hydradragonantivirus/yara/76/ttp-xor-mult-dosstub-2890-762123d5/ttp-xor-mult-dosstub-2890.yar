rule TTP_XOR_MULT_DOSStub_2890 {
  strings:
    $key_2890 = { 7c f8 [2] 08 e0 [2] 4f e2 [2] 08 f3 [2] 46 ff [2] 4a f5 [2] 5d fe [2] 46 b0 [2] 7b }

  condition:
    any of them
}