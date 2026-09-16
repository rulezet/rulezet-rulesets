rule TTP_XOR_MULT_DOSStub_de87 {
  strings:
    $key_de87 = { 8a ef [2] fe f7 [2] b9 f5 [2] fe e4 [2] b0 e8 [2] bc e2 [2] ab e9 [2] b0 a7 [2] 8d }

  condition:
    any of them
}