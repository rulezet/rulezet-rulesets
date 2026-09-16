rule TTP_XOR_MULT_DOSStub_0c68 {
  strings:
    $key_0c68 = { 58 00 [2] 2c 18 [2] 6b 1a [2] 2c 0b [2] 62 07 [2] 6e 0d [2] 79 06 [2] 62 48 [2] 5f }

  condition:
    any of them
}