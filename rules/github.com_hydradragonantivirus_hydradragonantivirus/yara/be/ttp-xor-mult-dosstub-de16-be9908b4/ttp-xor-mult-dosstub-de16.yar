rule TTP_XOR_MULT_DOSStub_de16 {
  strings:
    $key_de16 = { 8a 7e [2] fe 66 [2] b9 64 [2] fe 75 [2] b0 79 [2] bc 73 [2] ab 78 [2] b0 36 [2] 8d }

  condition:
    any of them
}