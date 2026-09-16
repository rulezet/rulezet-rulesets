rule TTP_XOR_MULT_DOSStub_7d4a {
  strings:
    $key_7d4a = { 29 22 [2] 5d 3a [2] 1a 38 [2] 5d 29 [2] 13 25 [2] 1f 2f [2] 08 24 [2] 13 6a [2] 2e }

  condition:
    any of them
}