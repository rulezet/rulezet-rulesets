rule TTP_XOR_MULT_DOSStub_de62 {
  strings:
    $key_de62 = { 8a 0a [2] fe 12 [2] b9 10 [2] fe 01 [2] b0 0d [2] bc 07 [2] ab 0c [2] b0 42 [2] 8d }

  condition:
    any of them
}