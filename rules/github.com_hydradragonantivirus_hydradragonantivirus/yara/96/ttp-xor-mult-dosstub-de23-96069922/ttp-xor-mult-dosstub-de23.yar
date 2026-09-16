rule TTP_XOR_MULT_DOSStub_de23 {
  strings:
    $key_de23 = { 8a 4b [2] fe 53 [2] b9 51 [2] fe 40 [2] b0 4c [2] bc 46 [2] ab 4d [2] b0 03 [2] 8d }

  condition:
    any of them
}