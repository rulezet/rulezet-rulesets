rule TTP_XOR_MULT_DOSStub_0e92 {
  strings:
    $key_0e92 = { 5a fa [2] 2e e2 [2] 69 e0 [2] 2e f1 [2] 60 fd [2] 6c f7 [2] 7b fc [2] 60 b2 [2] 5d }

  condition:
    any of them
}