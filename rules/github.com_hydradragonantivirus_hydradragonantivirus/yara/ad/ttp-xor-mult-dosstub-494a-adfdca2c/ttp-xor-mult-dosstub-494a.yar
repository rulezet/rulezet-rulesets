rule TTP_XOR_MULT_DOSStub_494a {
  strings:
    $key_494a = { 1d 22 [2] 69 3a [2] 2e 38 [2] 69 29 [2] 27 25 [2] 2b 2f [2] 3c 24 [2] 27 6a [2] 1a }

  condition:
    any of them
}