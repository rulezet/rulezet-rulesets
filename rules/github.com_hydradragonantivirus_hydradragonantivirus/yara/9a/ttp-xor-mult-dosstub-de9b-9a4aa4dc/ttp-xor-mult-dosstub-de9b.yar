rule TTP_XOR_MULT_DOSStub_de9b {
  strings:
    $key_de9b = { 8a f3 [2] fe eb [2] b9 e9 [2] fe f8 [2] b0 f4 [2] bc fe [2] ab f5 [2] b0 bb [2] 8d }

  condition:
    any of them
}