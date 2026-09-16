rule TTP_XOR_MULT_DOSStub_de28 {
  strings:
    $key_de28 = { 8a 40 [2] fe 58 [2] b9 5a [2] fe 4b [2] b0 47 [2] bc 4d [2] ab 46 [2] b0 08 [2] 8d }

  condition:
    any of them
}