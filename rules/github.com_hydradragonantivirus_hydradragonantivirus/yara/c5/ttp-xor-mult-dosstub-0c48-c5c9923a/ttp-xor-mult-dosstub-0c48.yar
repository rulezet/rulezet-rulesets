rule TTP_XOR_MULT_DOSStub_0c48 {
  strings:
    $key_0c48 = { 58 20 [2] 2c 38 [2] 6b 3a [2] 2c 2b [2] 62 27 [2] 6e 2d [2] 79 26 [2] 62 68 [2] 5f }

  condition:
    any of them
}