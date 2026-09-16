rule TTP_XOR_MULT_DOSStub_de48 {
  strings:
    $key_de48 = { 8a 20 [2] fe 38 [2] b9 3a [2] fe 2b [2] b0 27 [2] bc 2d [2] ab 26 [2] b0 68 [2] 8d }

  condition:
    any of them
}