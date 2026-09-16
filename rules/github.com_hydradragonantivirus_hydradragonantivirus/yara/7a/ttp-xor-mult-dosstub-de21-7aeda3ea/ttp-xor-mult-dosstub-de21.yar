rule TTP_XOR_MULT_DOSStub_de21 {
  strings:
    $key_de21 = { 8a 49 [2] fe 51 [2] b9 53 [2] fe 42 [2] b0 4e [2] bc 44 [2] ab 4f [2] b0 01 [2] 8d }

  condition:
    any of them
}