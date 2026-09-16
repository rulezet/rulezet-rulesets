rule TTP_XOR_MULT_DOSStub_0c2a {
  strings:
    $key_0c2a = { 58 42 [2] 2c 5a [2] 6b 58 [2] 2c 49 [2] 62 45 [2] 6e 4f [2] 79 44 [2] 62 0a [2] 5f }

  condition:
    any of them
}