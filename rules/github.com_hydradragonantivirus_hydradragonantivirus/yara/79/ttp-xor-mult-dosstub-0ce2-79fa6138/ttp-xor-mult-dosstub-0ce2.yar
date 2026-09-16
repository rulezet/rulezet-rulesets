rule TTP_XOR_MULT_DOSStub_0ce2 {
  strings:
    $key_0ce2 = { 58 8a [2] 2c 92 [2] 6b 90 [2] 2c 81 [2] 62 8d [2] 6e 87 [2] 79 8c [2] 62 c2 [2] 5f }

  condition:
    any of them
}