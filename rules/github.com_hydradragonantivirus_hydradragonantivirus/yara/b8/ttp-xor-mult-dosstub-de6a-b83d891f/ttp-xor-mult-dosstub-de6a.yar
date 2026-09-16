rule TTP_XOR_MULT_DOSStub_de6a {
  strings:
    $key_de6a = { 8a 02 [2] fe 1a [2] b9 18 [2] fe 09 [2] b0 05 [2] bc 0f [2] ab 04 [2] b0 4a [2] 8d }

  condition:
    any of them
}