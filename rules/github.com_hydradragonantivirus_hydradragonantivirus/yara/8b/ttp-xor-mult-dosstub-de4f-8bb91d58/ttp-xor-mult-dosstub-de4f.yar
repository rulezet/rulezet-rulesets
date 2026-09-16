rule TTP_XOR_MULT_DOSStub_de4f {
  strings:
    $key_de4f = { 8a 27 [2] fe 3f [2] b9 3d [2] fe 2c [2] b0 20 [2] bc 2a [2] ab 21 [2] b0 6f [2] 8d }

  condition:
    any of them
}