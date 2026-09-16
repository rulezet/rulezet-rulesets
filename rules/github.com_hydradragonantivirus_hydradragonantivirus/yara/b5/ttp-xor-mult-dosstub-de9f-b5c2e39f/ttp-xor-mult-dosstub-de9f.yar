rule TTP_XOR_MULT_DOSStub_de9f {
  strings:
    $key_de9f = { 8a f7 [2] fe ef [2] b9 ed [2] fe fc [2] b0 f0 [2] bc fa [2] ab f1 [2] b0 bf [2] 8d }

  condition:
    any of them
}