rule TTP_XOR_MULT_DOSStub_5d5a {
  strings:
    $key_5d5a = { 09 32 [2] 7d 2a [2] 3a 28 [2] 7d 39 [2] 33 35 [2] 3f 3f [2] 28 34 [2] 33 7a [2] 0e }

  condition:
    any of them
}