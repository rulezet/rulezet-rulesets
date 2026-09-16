rule TTP_XOR_MULT_DOSStub_0ce5 {
  strings:
    $key_0ce5 = { 58 8d [2] 2c 95 [2] 6b 97 [2] 2c 86 [2] 62 8a [2] 6e 80 [2] 79 8b [2] 62 c5 [2] 5f }

  condition:
    any of them
}