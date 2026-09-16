rule TTP_XOR_MULT_DOSStub_604a {
  strings:
    $key_604a = { 34 22 [2] 40 3a [2] 07 38 [2] 40 29 [2] 0e 25 [2] 02 2f [2] 15 24 [2] 0e 6a [2] 33 }

  condition:
    any of them
}