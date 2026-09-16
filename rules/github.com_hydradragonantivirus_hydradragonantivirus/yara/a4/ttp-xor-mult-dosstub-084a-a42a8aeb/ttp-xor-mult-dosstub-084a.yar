rule TTP_XOR_MULT_DOSStub_084a {
  strings:
    $key_084a = { 5c 22 [2] 28 3a [2] 6f 38 [2] 28 29 [2] 66 25 [2] 6a 2f [2] 7d 24 [2] 66 6a [2] 5b }

  condition:
    any of them
}