rule TTP_XOR_MULT_DOSStub_0c74 {
  strings:
    $key_0c74 = { 58 1c [2] 2c 04 [2] 6b 06 [2] 2c 17 [2] 62 1b [2] 6e 11 [2] 79 1a [2] 62 54 [2] 5f }

  condition:
    any of them
}