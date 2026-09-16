rule TTP_XOR_MULT_DOSStub_447a {
  strings:
    $key_447a = { 10 12 [2] 64 0a [2] 23 08 [2] 64 19 [2] 2a 15 [2] 26 1f [2] 31 14 [2] 2a 5a [2] 17 }

  condition:
    any of them
}