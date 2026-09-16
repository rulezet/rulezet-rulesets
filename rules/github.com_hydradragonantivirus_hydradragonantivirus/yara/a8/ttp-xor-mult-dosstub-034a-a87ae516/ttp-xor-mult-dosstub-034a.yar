rule TTP_XOR_MULT_DOSStub_034a {
  strings:
    $key_034a = { 57 22 [2] 23 3a [2] 64 38 [2] 23 29 [2] 6d 25 [2] 61 2f [2] 76 24 [2] 6d 6a [2] 50 }

  condition:
    any of them
}