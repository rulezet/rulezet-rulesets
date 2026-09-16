rule TTP_XOR_MULT_DOSStub_de18 {
  strings:
    $key_de18 = { 8a 70 [2] fe 68 [2] b9 6a [2] fe 7b [2] b0 77 [2] bc 7d [2] ab 76 [2] b0 38 [2] 8d }

  condition:
    any of them
}