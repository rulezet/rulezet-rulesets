rule TTP_XOR_MULT_DOSStub_0ce4 {
  strings:
    $key_0ce4 = { 58 8c [2] 2c 94 [2] 6b 96 [2] 2c 87 [2] 62 8b [2] 6e 81 [2] 79 8a [2] 62 c4 [2] 5f }

  condition:
    any of them
}