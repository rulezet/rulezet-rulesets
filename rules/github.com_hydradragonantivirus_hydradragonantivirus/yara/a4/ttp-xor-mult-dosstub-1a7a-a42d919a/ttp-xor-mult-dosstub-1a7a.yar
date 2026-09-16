rule TTP_XOR_MULT_DOSStub_1a7a {
  strings:
    $key_1a7a = { 4e 12 [2] 3a 0a [2] 7d 08 [2] 3a 19 [2] 74 15 [2] 78 1f [2] 6f 14 [2] 74 5a [2] 49 }

  condition:
    any of them
}