rule TTP_XOR_MULT_DOSStub_0c63 {
  strings:
    $key_0c63 = { 58 0b [2] 2c 13 [2] 6b 11 [2] 2c 00 [2] 62 0c [2] 6e 06 [2] 79 0d [2] 62 43 [2] 5f }

  condition:
    any of them
}