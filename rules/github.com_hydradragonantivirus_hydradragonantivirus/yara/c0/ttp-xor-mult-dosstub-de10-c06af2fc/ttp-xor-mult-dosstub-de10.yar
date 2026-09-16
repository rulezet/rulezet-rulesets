rule TTP_XOR_MULT_DOSStub_de10 {
  strings:
    $key_de10 = { 8a 78 [2] fe 60 [2] b9 62 [2] fe 73 [2] b0 7f [2] bc 75 [2] ab 7e [2] b0 30 [2] 8d }

  condition:
    any of them
}