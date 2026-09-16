rule TTP_XOR_MULT_DOSStub_0c1a {
  strings:
    $key_0c1a = { 58 72 [2] 2c 6a [2] 6b 68 [2] 2c 79 [2] 62 75 [2] 6e 7f [2] 79 74 [2] 62 3a [2] 5f }

  condition:
    any of them
}