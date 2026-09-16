rule TTP_XOR_MULT_DOSStub_0c15 {
  strings:
    $key_0c15 = { 58 7d [2] 2c 65 [2] 6b 67 [2] 2c 76 [2] 62 7a [2] 6e 70 [2] 79 7b [2] 62 35 [2] 5f }

  condition:
    any of them
}