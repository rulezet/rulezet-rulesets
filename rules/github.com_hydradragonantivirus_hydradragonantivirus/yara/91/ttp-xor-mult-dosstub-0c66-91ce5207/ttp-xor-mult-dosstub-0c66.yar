rule TTP_XOR_MULT_DOSStub_0c66 {
  strings:
    $key_0c66 = { 58 0e [2] 2c 16 [2] 6b 14 [2] 2c 05 [2] 62 09 [2] 6e 03 [2] 79 08 [2] 62 46 [2] 5f }

  condition:
    any of them
}