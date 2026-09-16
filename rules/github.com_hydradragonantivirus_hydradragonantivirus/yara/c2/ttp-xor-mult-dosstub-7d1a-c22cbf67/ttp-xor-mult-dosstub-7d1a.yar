rule TTP_XOR_MULT_DOSStub_7d1a {
  strings:
    $key_7d1a = { 29 72 [2] 5d 6a [2] 1a 68 [2] 5d 79 [2] 13 75 [2] 1f 7f [2] 08 74 [2] 13 3a [2] 2e }

  condition:
    any of them
}