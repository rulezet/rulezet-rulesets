rule TTP_XOR_MULT_DOSStub_1c4a {
  strings:
    $key_1c4a = { 48 22 [2] 3c 3a [2] 7b 38 [2] 3c 29 [2] 72 25 [2] 7e 2f [2] 69 24 [2] 72 6a [2] 4f }

  condition:
    any of them
}