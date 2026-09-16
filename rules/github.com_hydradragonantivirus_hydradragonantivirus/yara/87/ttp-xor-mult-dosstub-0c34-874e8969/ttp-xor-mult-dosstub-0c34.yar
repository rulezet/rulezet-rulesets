rule TTP_XOR_MULT_DOSStub_0c34 {
  strings:
    $key_0c34 = { 58 5c [2] 2c 44 [2] 6b 46 [2] 2c 57 [2] 62 5b [2] 6e 51 [2] 79 5a [2] 62 14 [2] 5f }

  condition:
    any of them
}