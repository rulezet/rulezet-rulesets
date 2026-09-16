rule TTP_XOR_MULT_DOSStub_de65 {
  strings:
    $key_de65 = { 8a 0d [2] fe 15 [2] b9 17 [2] fe 06 [2] b0 0a [2] bc 00 [2] ab 0b [2] b0 45 [2] 8d }

  condition:
    any of them
}