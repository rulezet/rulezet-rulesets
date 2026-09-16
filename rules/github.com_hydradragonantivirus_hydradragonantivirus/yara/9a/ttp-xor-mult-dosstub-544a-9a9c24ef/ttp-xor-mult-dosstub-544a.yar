rule TTP_XOR_MULT_DOSStub_544a {
  strings:
    $key_544a = { 00 22 [2] 74 3a [2] 33 38 [2] 74 29 [2] 3a 25 [2] 36 2f [2] 21 24 [2] 3a 6a [2] 07 }

  condition:
    any of them
}