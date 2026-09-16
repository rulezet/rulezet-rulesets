rule TTP_XOR_MULT_DOSStub_de92 {
  strings:
    $key_de92 = { 8a fa [2] fe e2 [2] b9 e0 [2] fe f1 [2] b0 fd [2] bc f7 [2] ab fc [2] b0 b2 [2] 8d }

  condition:
    any of them
}