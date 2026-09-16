rule TTP_XOR_MULT_DOSStub_de53 {
  strings:
    $key_de53 = { 8a 3b [2] fe 23 [2] b9 21 [2] fe 30 [2] b0 3c [2] bc 36 [2] ab 3d [2] b0 73 [2] 8d }

  condition:
    any of them
}