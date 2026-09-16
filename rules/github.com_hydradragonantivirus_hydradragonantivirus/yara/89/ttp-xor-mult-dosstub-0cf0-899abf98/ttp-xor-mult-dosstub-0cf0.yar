rule TTP_XOR_MULT_DOSStub_0cf0 {
  strings:
    $key_0cf0 = { 58 98 [2] 2c 80 [2] 6b 82 [2] 2c 93 [2] 62 9f [2] 6e 95 [2] 79 9e [2] 62 d0 [2] 5f }

  condition:
    any of them
}