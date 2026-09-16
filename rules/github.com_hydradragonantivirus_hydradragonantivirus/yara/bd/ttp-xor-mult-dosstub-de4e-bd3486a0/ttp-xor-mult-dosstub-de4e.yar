rule TTP_XOR_MULT_DOSStub_de4e {
  strings:
    $key_de4e = { 8a 26 [2] fe 3e [2] b9 3c [2] fe 2d [2] b0 21 [2] bc 2b [2] ab 20 [2] b0 6e [2] 8d }

  condition:
    any of them
}