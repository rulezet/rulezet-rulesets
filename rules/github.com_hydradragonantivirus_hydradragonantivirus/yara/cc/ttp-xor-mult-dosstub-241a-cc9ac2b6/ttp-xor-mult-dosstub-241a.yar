rule TTP_XOR_MULT_DOSStub_241a {
  strings:
    $key_241a = { 70 72 [2] 04 6a [2] 43 68 [2] 04 79 [2] 4a 75 [2] 46 7f [2] 51 74 [2] 4a 3a [2] 77 }

  condition:
    any of them
}