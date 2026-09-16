rule TTP_XOR_MULT_DOSStub_5d1a {
  strings:
    $key_5d1a = { 09 72 [2] 7d 6a [2] 3a 68 [2] 7d 79 [2] 33 75 [2] 3f 7f [2] 28 74 [2] 33 3a [2] 0e }

  condition:
    any of them
}