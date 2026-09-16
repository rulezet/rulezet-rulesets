rule TTP_XOR_MULT_DOSStub_0cfa {
  strings:
    $key_0cfa = { 58 92 [2] 2c 8a [2] 6b 88 [2] 2c 99 [2] 62 95 [2] 6e 9f [2] 79 94 [2] 62 da [2] 5f }

  condition:
    any of them
}