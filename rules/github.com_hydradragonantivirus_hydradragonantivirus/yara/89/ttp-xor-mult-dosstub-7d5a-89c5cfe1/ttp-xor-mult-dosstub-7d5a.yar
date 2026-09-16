rule TTP_XOR_MULT_DOSStub_7d5a {
  strings:
    $key_7d5a = { 29 32 [2] 5d 2a [2] 1a 28 [2] 5d 39 [2] 13 35 [2] 1f 3f [2] 08 34 [2] 13 7a [2] 2e }

  condition:
    any of them
}