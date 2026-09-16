rule TTP_XOR_MULT_DOSStub_de6f {
  strings:
    $key_de6f = { 8a 07 [2] fe 1f [2] b9 1d [2] fe 0c [2] b0 00 [2] bc 0a [2] ab 01 [2] b0 4f [2] 8d }

  condition:
    any of them
}