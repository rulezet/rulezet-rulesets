rule TTP_XOR_MULT_DOSStub_284a {
  strings:
    $key_284a = { 7c 22 [2] 08 3a [2] 4f 38 [2] 08 29 [2] 46 25 [2] 4a 2f [2] 5d 24 [2] 46 6a [2] 7b }

  condition:
    any of them
}