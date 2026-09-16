rule TTP_XOR_MULT_DOSStub_de41 {
  strings:
    $key_de41 = { 8a 29 [2] fe 31 [2] b9 33 [2] fe 22 [2] b0 2e [2] bc 24 [2] ab 2f [2] b0 61 [2] 8d }

  condition:
    any of them
}