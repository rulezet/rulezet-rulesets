rule TTP_XOR_MULT_DOSStub_5d7a {
  strings:
    $key_5d7a = { 09 12 [2] 7d 0a [2] 3a 08 [2] 7d 19 [2] 33 15 [2] 3f 1f [2] 28 14 [2] 33 5a [2] 0e }

  condition:
    any of them
}