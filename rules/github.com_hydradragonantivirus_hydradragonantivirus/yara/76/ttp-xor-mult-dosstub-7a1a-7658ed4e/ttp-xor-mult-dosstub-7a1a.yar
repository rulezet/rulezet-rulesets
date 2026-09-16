rule TTP_XOR_MULT_DOSStub_7a1a {
  strings:
    $key_7a1a = { 2e 72 [2] 5a 6a [2] 1d 68 [2] 5a 79 [2] 14 75 [2] 18 7f [2] 0f 74 [2] 14 3a [2] 29 }

  condition:
    any of them
}