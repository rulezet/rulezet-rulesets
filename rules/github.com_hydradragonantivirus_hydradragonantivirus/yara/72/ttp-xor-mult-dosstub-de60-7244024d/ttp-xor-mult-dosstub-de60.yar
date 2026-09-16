rule TTP_XOR_MULT_DOSStub_de60 {
  strings:
    $key_de60 = { 8a 08 [2] fe 10 [2] b9 12 [2] fe 03 [2] b0 0f [2] bc 05 [2] ab 0e [2] b0 40 [2] 8d }

  condition:
    any of them
}