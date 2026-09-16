rule TTP_XOR_MULT_DOSStub_7096 {
  strings:
    $key_7096 = { 24 fe [2] 50 e6 [2] 17 e4 [2] 50 f5 [2] 1e f9 [2] 12 f3 [2] 05 f8 [2] 1e b6 [2] 23 }

  condition:
    any of them
}