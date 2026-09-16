rule TTP_XOR_MULT_DOSStub_7e92 {
  strings:
    $key_7e92 = { 2a fa [2] 5e e2 [2] 19 e0 [2] 5e f1 [2] 10 fd [2] 1c f7 [2] 0b fc [2] 10 b2 [2] 2d }

  condition:
    any of them
}