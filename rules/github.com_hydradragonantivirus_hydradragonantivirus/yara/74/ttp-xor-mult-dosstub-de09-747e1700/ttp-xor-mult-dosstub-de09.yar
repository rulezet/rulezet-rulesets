rule TTP_XOR_MULT_DOSStub_de09 {
  strings:
    $key_de09 = { 8a 61 [2] fe 79 [2] b9 7b [2] fe 6a [2] b0 66 [2] bc 6c [2] ab 67 [2] b0 29 [2] 8d }

  condition:
    any of them
}