rule TTP_XOR_MULT_DOSStub_021a {
  strings:
    $key_021a = { 56 72 [2] 22 6a [2] 65 68 [2] 22 79 [2] 6c 75 [2] 60 7f [2] 77 74 [2] 6c 3a [2] 51 }

  condition:
    any of them
}