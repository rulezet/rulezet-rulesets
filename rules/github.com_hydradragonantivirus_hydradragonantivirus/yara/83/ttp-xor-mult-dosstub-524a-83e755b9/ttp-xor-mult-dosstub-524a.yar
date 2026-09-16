rule TTP_XOR_MULT_DOSStub_524a {
  strings:
    $key_524a = { 06 22 [2] 72 3a [2] 35 38 [2] 72 29 [2] 3c 25 [2] 30 2f [2] 27 24 [2] 3c 6a [2] 01 }

  condition:
    any of them
}