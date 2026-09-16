rule TTP_XOR_MULT_DOSStub_5d4a {
  strings:
    $key_5d4a = { 09 22 [2] 7d 3a [2] 3a 38 [2] 7d 29 [2] 33 25 [2] 3f 2f [2] 28 24 [2] 33 6a [2] 0e }

  condition:
    any of them
}