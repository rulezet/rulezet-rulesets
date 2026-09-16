rule TTP_XOR_MULT_DOSStub_de37 {
  strings:
    $key_de37 = { 8a 5f [2] fe 47 [2] b9 45 [2] fe 54 [2] b0 58 [2] bc 52 [2] ab 59 [2] b0 17 [2] 8d }

  condition:
    any of them
}