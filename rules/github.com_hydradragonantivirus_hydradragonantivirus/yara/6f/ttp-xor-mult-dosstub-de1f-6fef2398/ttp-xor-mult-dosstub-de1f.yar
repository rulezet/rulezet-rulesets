rule TTP_XOR_MULT_DOSStub_de1f {
  strings:
    $key_de1f = { 8a 77 [2] fe 6f [2] b9 6d [2] fe 7c [2] b0 70 [2] bc 7a [2] ab 71 [2] b0 3f [2] 8d }

  condition:
    any of them
}