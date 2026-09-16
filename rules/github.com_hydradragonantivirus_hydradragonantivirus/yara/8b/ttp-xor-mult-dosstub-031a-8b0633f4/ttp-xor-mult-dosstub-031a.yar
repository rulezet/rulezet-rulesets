rule TTP_XOR_MULT_DOSStub_031a {
  strings:
    $key_031a = { 57 72 [2] 23 6a [2] 64 68 [2] 23 79 [2] 6d 75 [2] 61 7f [2] 76 74 [2] 6d 3a [2] 50 }

  condition:
    any of them
}