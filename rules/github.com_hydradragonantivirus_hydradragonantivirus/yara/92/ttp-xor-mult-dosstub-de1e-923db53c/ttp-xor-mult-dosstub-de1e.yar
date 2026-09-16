rule TTP_XOR_MULT_DOSStub_de1e {
  strings:
    $key_de1e = { 8a 76 [2] fe 6e [2] b9 6c [2] fe 7d [2] b0 71 [2] bc 7b [2] ab 70 [2] b0 3e [2] 8d }

  condition:
    any of them
}