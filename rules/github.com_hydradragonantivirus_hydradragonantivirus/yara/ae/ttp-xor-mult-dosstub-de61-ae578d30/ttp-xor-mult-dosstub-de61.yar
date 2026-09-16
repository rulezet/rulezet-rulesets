rule TTP_XOR_MULT_DOSStub_de61 {
  strings:
    $key_de61 = { 8a 09 [2] fe 11 [2] b9 13 [2] fe 02 [2] b0 0e [2] bc 04 [2] ab 0f [2] b0 41 [2] 8d }

  condition:
    any of them
}