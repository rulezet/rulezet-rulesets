rule TTP_XOR_MULT_DOSStub_de5d {
  strings:
    $key_de5d = { 8a 35 [2] fe 2d [2] b9 2f [2] fe 3e [2] b0 32 [2] bc 38 [2] ab 33 [2] b0 7d [2] 8d }

  condition:
    any of them
}