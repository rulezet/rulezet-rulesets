rule TTP_XOR_MULT_DOSStub_0c61 {
  strings:
    $key_0c61 = { 58 09 [2] 2c 11 [2] 6b 13 [2] 2c 02 [2] 62 0e [2] 6e 04 [2] 79 0f [2] 62 41 [2] 5f }

  condition:
    any of them
}