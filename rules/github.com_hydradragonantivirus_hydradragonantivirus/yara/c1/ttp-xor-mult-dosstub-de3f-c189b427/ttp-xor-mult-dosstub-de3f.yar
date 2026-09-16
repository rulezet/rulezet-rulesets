rule TTP_XOR_MULT_DOSStub_de3f {
  strings:
    $key_de3f = { 8a 57 [2] fe 4f [2] b9 4d [2] fe 5c [2] b0 50 [2] bc 5a [2] ab 51 [2] b0 1f [2] 8d }

  condition:
    any of them
}