rule TTP_XOR_MULT_DOSStub_0c70 {
  strings:
    $key_0c70 = { 58 18 [2] 2c 00 [2] 6b 02 [2] 2c 13 [2] 62 1f [2] 6e 15 [2] 79 1e [2] 62 50 [2] 5f }

  condition:
    any of them
}