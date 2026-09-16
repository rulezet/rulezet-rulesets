rule TTP_XOR_MULT_DOSStub_de08 {
  strings:
    $key_de08 = { 8a 60 [2] fe 78 [2] b9 7a [2] fe 6b [2] b0 67 [2] bc 6d [2] ab 66 [2] b0 28 [2] 8d }

  condition:
    any of them
}