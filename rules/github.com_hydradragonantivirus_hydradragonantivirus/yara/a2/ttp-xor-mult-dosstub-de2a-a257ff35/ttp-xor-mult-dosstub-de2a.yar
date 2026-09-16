rule TTP_XOR_MULT_DOSStub_de2a {
  strings:
    $key_de2a = { 8a 42 [2] fe 5a [2] b9 58 [2] fe 49 [2] b0 45 [2] bc 4f [2] ab 44 [2] b0 0a [2] 8d }

  condition:
    any of them
}