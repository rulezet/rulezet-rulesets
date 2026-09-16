rule TTP_XOR_MULT_DOSStub_de02 {
  strings:
    $key_de02 = { 8a 6a [2] fe 72 [2] b9 70 [2] fe 61 [2] b0 6d [2] bc 67 [2] ab 6c [2] b0 22 [2] 8d }

  condition:
    any of them
}