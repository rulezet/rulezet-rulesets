rule TTP_XOR_MULT_DOSStub_714a {
  strings:
    $key_714a = { 25 22 [2] 51 3a [2] 16 38 [2] 51 29 [2] 1f 25 [2] 13 2f [2] 04 24 [2] 1f 6a [2] 22 }

  condition:
    any of them
}