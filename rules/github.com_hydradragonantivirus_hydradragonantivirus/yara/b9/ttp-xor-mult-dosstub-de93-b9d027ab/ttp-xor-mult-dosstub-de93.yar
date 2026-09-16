rule TTP_XOR_MULT_DOSStub_de93 {
  strings:
    $key_de93 = { 8a fb [2] fe e3 [2] b9 e1 [2] fe f0 [2] b0 fc [2] bc f6 [2] ab fd [2] b0 b3 [2] 8d }

  condition:
    any of them
}