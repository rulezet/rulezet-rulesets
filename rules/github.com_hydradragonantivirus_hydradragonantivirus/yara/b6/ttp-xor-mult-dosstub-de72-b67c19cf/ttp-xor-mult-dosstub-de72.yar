rule TTP_XOR_MULT_DOSStub_de72 {
  strings:
    $key_de72 = { 8a 1a [2] fe 02 [2] b9 00 [2] fe 11 [2] b0 1d [2] bc 17 [2] ab 1c [2] b0 52 [2] 8d }

  condition:
    any of them
}