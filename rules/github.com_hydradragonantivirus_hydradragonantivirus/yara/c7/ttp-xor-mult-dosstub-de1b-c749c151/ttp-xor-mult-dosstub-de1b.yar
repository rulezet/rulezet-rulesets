rule TTP_XOR_MULT_DOSStub_de1b {
  strings:
    $key_de1b = { 8a 73 [2] fe 6b [2] b9 69 [2] fe 78 [2] b0 74 [2] bc 7e [2] ab 75 [2] b0 3b [2] 8d }

  condition:
    any of them
}