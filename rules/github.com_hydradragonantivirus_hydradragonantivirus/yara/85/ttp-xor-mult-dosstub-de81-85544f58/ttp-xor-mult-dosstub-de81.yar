rule TTP_XOR_MULT_DOSStub_de81 {
  strings:
    $key_de81 = { 8a e9 [2] fe f1 [2] b9 f3 [2] fe e2 [2] b0 ee [2] bc e4 [2] ab ef [2] b0 a1 [2] 8d }

  condition:
    any of them
}