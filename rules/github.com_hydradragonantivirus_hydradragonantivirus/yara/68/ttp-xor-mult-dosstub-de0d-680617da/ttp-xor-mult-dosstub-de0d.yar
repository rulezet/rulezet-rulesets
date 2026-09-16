rule TTP_XOR_MULT_DOSStub_de0d {
  strings:
    $key_de0d = { 8a 65 [2] fe 7d [2] b9 7f [2] fe 6e [2] b0 62 [2] bc 68 [2] ab 63 [2] b0 2d [2] 8d }

  condition:
    any of them
}