rule TTP_XOR_MULT_DOSStub_7a4a {
  strings:
    $key_7a4a = { 2e 22 [2] 5a 3a [2] 1d 38 [2] 5a 29 [2] 14 25 [2] 18 2f [2] 0f 24 [2] 14 6a [2] 29 }

  condition:
    any of them
}