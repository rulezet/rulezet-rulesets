rule TTP_XOR_MULT_DOSStub_de90 {
  strings:
    $key_de90 = { 8a f8 [2] fe e0 [2] b9 e2 [2] fe f3 [2] b0 ff [2] bc f5 [2] ab fe [2] b0 b0 [2] 8d }

  condition:
    any of them
}