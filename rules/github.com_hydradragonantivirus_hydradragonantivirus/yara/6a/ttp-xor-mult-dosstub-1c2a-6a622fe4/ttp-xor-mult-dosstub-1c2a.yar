rule TTP_XOR_MULT_DOSStub_1c2a {
  strings:
    $key_1c2a = { 48 42 [2] 3c 5a [2] 7b 58 [2] 3c 49 [2] 72 45 [2] 7e 4f [2] 69 44 [2] 72 0a [2] 4f }

  condition:
    any of them
}