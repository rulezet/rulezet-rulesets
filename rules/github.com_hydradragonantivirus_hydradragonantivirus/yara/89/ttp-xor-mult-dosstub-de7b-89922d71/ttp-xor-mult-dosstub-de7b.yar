rule TTP_XOR_MULT_DOSStub_de7b {
  strings:
    $key_de7b = { 8a 13 [2] fe 0b [2] b9 09 [2] fe 18 [2] b0 14 [2] bc 1e [2] ab 15 [2] b0 5b [2] 8d }

  condition:
    any of them
}