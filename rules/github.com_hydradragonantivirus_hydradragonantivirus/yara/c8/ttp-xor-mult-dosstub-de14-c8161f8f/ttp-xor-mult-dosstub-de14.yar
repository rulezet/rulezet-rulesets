rule TTP_XOR_MULT_DOSStub_de14 {
  strings:
    $key_de14 = { 8a 7c [2] fe 64 [2] b9 66 [2] fe 77 [2] b0 7b [2] bc 71 [2] ab 7a [2] b0 34 [2] 8d }

  condition:
    any of them
}