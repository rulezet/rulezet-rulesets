rule TTP_XOR_MULT_DOSStub_de38 {
  strings:
    $key_de38 = { 8a 50 [2] fe 48 [2] b9 4a [2] fe 5b [2] b0 57 [2] bc 5d [2] ab 56 [2] b0 18 [2] 8d }

  condition:
    any of them
}