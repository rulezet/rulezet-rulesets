rule TTP_XOR_MULT_DOSStub_de4b {
  strings:
    $key_de4b = { 8a 23 [2] fe 3b [2] b9 39 [2] fe 28 [2] b0 24 [2] bc 2e [2] ab 25 [2] b0 6b [2] 8d }

  condition:
    any of them
}