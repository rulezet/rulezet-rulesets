rule TTP_XOR_MULT_DOSStub_de54 {
  strings:
    $key_de54 = { 8a 3c [2] fe 24 [2] b9 26 [2] fe 37 [2] b0 3b [2] bc 31 [2] ab 3a [2] b0 74 [2] 8d }

  condition:
    any of them
}