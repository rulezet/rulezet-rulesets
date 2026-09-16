rule TTP_XOR_MULT_DOSStub_0c3f {
  strings:
    $key_0c3f = { 58 57 [2] 2c 4f [2] 6b 4d [2] 2c 5c [2] 62 50 [2] 6e 5a [2] 79 51 [2] 62 1f [2] 5f }

  condition:
    any of them
}