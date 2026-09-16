rule TTP_XOR_MULT_DOSStub_de6e {
  strings:
    $key_de6e = { 8a 06 [2] fe 1e [2] b9 1c [2] fe 0d [2] b0 01 [2] bc 0b [2] ab 00 [2] b0 4e [2] 8d }

  condition:
    any of them
}