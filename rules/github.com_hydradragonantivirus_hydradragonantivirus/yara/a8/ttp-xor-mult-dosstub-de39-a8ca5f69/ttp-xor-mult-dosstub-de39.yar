rule TTP_XOR_MULT_DOSStub_de39 {
  strings:
    $key_de39 = { 8a 51 [2] fe 49 [2] b9 4b [2] fe 5a [2] b0 56 [2] bc 5c [2] ab 57 [2] b0 19 [2] 8d }

  condition:
    any of them
}