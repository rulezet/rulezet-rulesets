rule TTP_XOR_MULT_DOSStub_735a {
  strings:
    $key_735a = { 27 32 [2] 53 2a [2] 14 28 [2] 53 39 [2] 1d 35 [2] 11 3f [2] 06 34 [2] 1d 7a [2] 20 }

  condition:
    any of them
}