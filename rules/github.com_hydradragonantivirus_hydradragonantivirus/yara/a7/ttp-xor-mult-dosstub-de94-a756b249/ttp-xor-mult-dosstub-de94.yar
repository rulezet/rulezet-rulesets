rule TTP_XOR_MULT_DOSStub_de94 {
  strings:
    $key_de94 = { 8a fc [2] fe e4 [2] b9 e6 [2] fe f7 [2] b0 fb [2] bc f1 [2] ab fa [2] b0 b4 [2] 8d }

  condition:
    any of them
}