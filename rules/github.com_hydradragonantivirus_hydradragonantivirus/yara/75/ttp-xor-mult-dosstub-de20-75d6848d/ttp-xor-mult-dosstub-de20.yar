rule TTP_XOR_MULT_DOSStub_de20 {
  strings:
    $key_de20 = { 8a 48 [2] fe 50 [2] b9 52 [2] fe 43 [2] b0 4f [2] bc 45 [2] ab 4e [2] b0 00 [2] 8d }

  condition:
    any of them
}