rule TTP_XOR_MULT_DOSStub_744a {
  strings:
    $key_744a = { 20 22 [2] 54 3a [2] 13 38 [2] 54 29 [2] 1a 25 [2] 16 2f [2] 01 24 [2] 1a 6a [2] 27 }

  condition:
    any of them
}