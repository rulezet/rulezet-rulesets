rule TTP_XOR_MULT_DOSStub_0c32 {
  strings:
    $key_0c32 = { 58 5a [2] 2c 42 [2] 6b 40 [2] 2c 51 [2] 62 5d [2] 6e 57 [2] 79 5c [2] 62 12 [2] 5f }

  condition:
    any of them
}