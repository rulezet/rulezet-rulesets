rule TTP_XOR_MULT_DOSStub_de33 {
  strings:
    $key_de33 = { 8a 5b [2] fe 43 [2] b9 41 [2] fe 50 [2] b0 5c [2] bc 56 [2] ab 5d [2] b0 13 [2] 8d }

  condition:
    any of them
}