rule TTP_XOR_MULT_DOSStub_de01 {
  strings:
    $key_de01 = { 8a 69 [2] fe 71 [2] b9 73 [2] fe 62 [2] b0 6e [2] bc 64 [2] ab 6f [2] b0 21 [2] 8d }

  condition:
    any of them
}