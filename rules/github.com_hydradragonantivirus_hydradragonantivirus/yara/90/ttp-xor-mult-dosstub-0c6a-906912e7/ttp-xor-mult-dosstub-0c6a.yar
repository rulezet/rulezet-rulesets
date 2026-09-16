rule TTP_XOR_MULT_DOSStub_0c6a {
  strings:
    $key_0c6a = { 58 02 [2] 2c 1a [2] 6b 18 [2] 2c 09 [2] 62 05 [2] 6e 0f [2] 79 04 [2] 62 4a [2] 5f }

  condition:
    any of them
}