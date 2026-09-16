rule TTP_XOR_MULT_DOSStub_0c79 {
  strings:
    $key_0c79 = { 58 11 [2] 2c 09 [2] 6b 0b [2] 2c 1a [2] 62 16 [2] 6e 1c [2] 79 17 [2] 62 59 [2] 5f }

  condition:
    any of them
}