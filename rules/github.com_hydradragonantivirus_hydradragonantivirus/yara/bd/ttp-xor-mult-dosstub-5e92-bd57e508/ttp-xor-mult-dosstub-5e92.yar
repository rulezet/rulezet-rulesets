rule TTP_XOR_MULT_DOSStub_5e92 {
  strings:
    $key_5e92 = { 0a fa [2] 7e e2 [2] 39 e0 [2] 7e f1 [2] 30 fd [2] 3c f7 [2] 2b fc [2] 30 b2 [2] 0d }

  condition:
    any of them
}