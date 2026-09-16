rule TTP_XOR_MULT_DOSStub_de59 {
  strings:
    $key_de59 = { 8a 31 [2] fe 29 [2] b9 2b [2] fe 3a [2] b0 36 [2] bc 3c [2] ab 37 [2] b0 79 [2] 8d }

  condition:
    any of them
}