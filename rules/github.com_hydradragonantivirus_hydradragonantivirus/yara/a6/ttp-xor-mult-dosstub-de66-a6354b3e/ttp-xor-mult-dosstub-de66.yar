rule TTP_XOR_MULT_DOSStub_de66 {
  strings:
    $key_de66 = { 8a 0e [2] fe 16 [2] b9 14 [2] fe 05 [2] b0 09 [2] bc 03 [2] ab 08 [2] b0 46 [2] 8d }

  condition:
    any of them
}