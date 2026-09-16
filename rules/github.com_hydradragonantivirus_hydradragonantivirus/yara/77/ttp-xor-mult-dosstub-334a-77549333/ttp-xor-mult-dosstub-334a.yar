rule TTP_XOR_MULT_DOSStub_334a {
  strings:
    $key_334a = { 67 22 [2] 13 3a [2] 54 38 [2] 13 29 [2] 5d 25 [2] 51 2f [2] 46 24 [2] 5d 6a [2] 60 }

  condition:
    any of them
}