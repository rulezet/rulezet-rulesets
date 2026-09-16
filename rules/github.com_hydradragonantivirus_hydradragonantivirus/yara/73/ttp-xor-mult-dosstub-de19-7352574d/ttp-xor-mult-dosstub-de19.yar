rule TTP_XOR_MULT_DOSStub_de19 {
  strings:
    $key_de19 = { 8a 71 [2] fe 69 [2] b9 6b [2] fe 7a [2] b0 76 [2] bc 7c [2] ab 77 [2] b0 39 [2] 8d }

  condition:
    any of them
}