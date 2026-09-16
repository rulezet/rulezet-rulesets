rule TTP_XOR_MULT_DOSStub_0c75 {
  strings:
    $key_0c75 = { 58 1d [2] 2c 05 [2] 6b 07 [2] 2c 16 [2] 62 1a [2] 6e 10 [2] 79 1b [2] 62 55 [2] 5f }

  condition:
    any of them
}