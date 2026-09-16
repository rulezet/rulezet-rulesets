rule TTP_XOR_MULT_DOSStub_de31 {
  strings:
    $key_de31 = { 8a 59 [2] fe 41 [2] b9 43 [2] fe 52 [2] b0 5e [2] bc 54 [2] ab 5f [2] b0 11 [2] 8d }

  condition:
    any of them
}