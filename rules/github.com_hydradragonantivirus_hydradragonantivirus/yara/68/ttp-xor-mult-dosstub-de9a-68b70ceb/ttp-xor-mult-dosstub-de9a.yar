rule TTP_XOR_MULT_DOSStub_de9a {
  strings:
    $key_de9a = { 8a f2 [2] fe ea [2] b9 e8 [2] fe f9 [2] b0 f5 [2] bc ff [2] ab f4 [2] b0 ba [2] 8d }

  condition:
    any of them
}