rule TTP_XOR_MULT_DOSStub_de76 {
  strings:
    $key_de76 = { 8a 1e [2] fe 06 [2] b9 04 [2] fe 15 [2] b0 19 [2] bc 13 [2] ab 18 [2] b0 56 [2] 8d }

  condition:
    any of them
}