rule TTP_XOR_MULT_DOSStub_0cf7 {
  strings:
    $key_0cf7 = { 58 9f [2] 2c 87 [2] 6b 85 [2] 2c 94 [2] 62 98 [2] 6e 92 [2] 79 99 [2] 62 d7 [2] 5f }

  condition:
    any of them
}