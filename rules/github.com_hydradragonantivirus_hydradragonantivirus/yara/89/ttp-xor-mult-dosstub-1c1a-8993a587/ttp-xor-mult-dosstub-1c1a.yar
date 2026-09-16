rule TTP_XOR_MULT_DOSStub_1c1a {
  strings:
    $key_1c1a = { 48 72 [2] 3c 6a [2] 7b 68 [2] 3c 79 [2] 72 75 [2] 7e 7f [2] 69 74 [2] 72 3a [2] 4f }

  condition:
    any of them
}