rule TTP_XOR_MULT_DOSStub_de25 {
  strings:
    $key_de25 = { 8a 4d [2] fe 55 [2] b9 57 [2] fe 46 [2] b0 4a [2] bc 40 [2] ab 4b [2] b0 05 [2] 8d }

  condition:
    any of them
}