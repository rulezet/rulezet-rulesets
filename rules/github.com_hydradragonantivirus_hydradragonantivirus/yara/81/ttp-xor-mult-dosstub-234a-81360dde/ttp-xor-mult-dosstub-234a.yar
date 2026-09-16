rule TTP_XOR_MULT_DOSStub_234a {
  strings:
    $key_234a = { 77 22 [2] 03 3a [2] 44 38 [2] 03 29 [2] 4d 25 [2] 41 2f [2] 56 24 [2] 4d 6a [2] 70 }

  condition:
    any of them
}