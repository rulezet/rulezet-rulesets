rule TTP_XOR_MULT_DOSStub_de29 {
  strings:
    $key_de29 = { 8a 41 [2] fe 59 [2] b9 5b [2] fe 4a [2] b0 46 [2] bc 4c [2] ab 47 [2] b0 09 [2] 8d }

  condition:
    any of them
}