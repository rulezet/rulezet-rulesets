rule TTP_XOR_MULT_DOSStub_0c45 {
  strings:
    $key_0c45 = { 58 2d [2] 2c 35 [2] 6b 37 [2] 2c 26 [2] 62 2a [2] 6e 20 [2] 79 2b [2] 62 65 [2] 5f }

  condition:
    any of them
}