rule TTP_XOR_MULT_DOSStub_673a {
  strings:
    $key_673a = { 33 52 [2] 47 4a [2] 00 48 [2] 47 59 [2] 09 55 [2] 05 5f [2] 12 54 [2] 09 1a [2] 34 }

  condition:
    any of them
}