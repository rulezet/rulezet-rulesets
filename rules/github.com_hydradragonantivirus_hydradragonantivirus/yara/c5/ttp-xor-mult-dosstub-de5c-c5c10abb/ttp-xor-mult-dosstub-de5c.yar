rule TTP_XOR_MULT_DOSStub_de5c {
  strings:
    $key_de5c = { 8a 34 [2] fe 2c [2] b9 2e [2] fe 3f [2] b0 33 [2] bc 39 [2] ab 32 [2] b0 7c [2] 8d }

  condition:
    any of them
}