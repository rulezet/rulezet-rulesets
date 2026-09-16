rule TTP_XOR_MULT_DOSStub_454a {
  strings:
    $key_454a = { 11 22 [2] 65 3a [2] 22 38 [2] 65 29 [2] 2b 25 [2] 27 2f [2] 30 24 [2] 2b 6a [2] 16 }

  condition:
    any of them
}