rule TTP_XOR_MULT_DOSStub_de44 {
  strings:
    $key_de44 = { 8a 2c [2] fe 34 [2] b9 36 [2] fe 27 [2] b0 2b [2] bc 21 [2] ab 2a [2] b0 64 [2] 8d }

  condition:
    any of them
}