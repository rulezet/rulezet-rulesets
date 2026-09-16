rule TTP_XOR_MULT_DOSStub_de79 {
  strings:
    $key_de79 = { 8a 11 [2] fe 09 [2] b9 0b [2] fe 1a [2] b0 16 [2] bc 1c [2] ab 17 [2] b0 59 [2] 8d }

  condition:
    any of them
}