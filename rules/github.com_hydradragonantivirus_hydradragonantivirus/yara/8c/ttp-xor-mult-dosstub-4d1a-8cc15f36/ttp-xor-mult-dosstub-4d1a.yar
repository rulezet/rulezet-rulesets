rule TTP_XOR_MULT_DOSStub_4d1a {
  strings:
    $key_4d1a = { 19 72 [2] 6d 6a [2] 2a 68 [2] 6d 79 [2] 23 75 [2] 2f 7f [2] 38 74 [2] 23 3a [2] 1e }

  condition:
    any of them
}