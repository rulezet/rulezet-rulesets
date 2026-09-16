rule TTP_XOR_MULT_DOSStub_671a {
  strings:
    $key_671a = { 33 72 [2] 47 6a [2] 00 68 [2] 47 79 [2] 09 75 [2] 05 7f [2] 12 74 [2] 09 3a [2] 34 }

  condition:
    any of them
}