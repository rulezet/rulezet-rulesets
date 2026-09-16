rule TTP_XOR_MULT_DOSStub_de0b {
  strings:
    $key_de0b = { 8a 63 [2] fe 7b [2] b9 79 [2] fe 68 [2] b0 64 [2] bc 6e [2] ab 65 [2] b0 2b [2] 8d }

  condition:
    any of them
}