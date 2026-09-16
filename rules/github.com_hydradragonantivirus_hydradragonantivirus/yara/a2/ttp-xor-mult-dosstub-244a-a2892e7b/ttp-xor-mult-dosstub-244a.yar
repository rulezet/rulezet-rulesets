rule TTP_XOR_MULT_DOSStub_244a {
  strings:
    $key_244a = { 70 22 [2] 04 3a [2] 43 38 [2] 04 29 [2] 4a 25 [2] 46 2f [2] 51 24 [2] 4a 6a [2] 77 }

  condition:
    any of them
}