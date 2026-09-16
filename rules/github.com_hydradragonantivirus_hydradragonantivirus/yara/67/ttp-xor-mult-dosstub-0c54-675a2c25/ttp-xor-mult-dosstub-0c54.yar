rule TTP_XOR_MULT_DOSStub_0c54 {
  strings:
    $key_0c54 = { 58 3c [2] 2c 24 [2] 6b 26 [2] 2c 37 [2] 62 3b [2] 6e 31 [2] 79 3a [2] 62 74 [2] 5f }

  condition:
    any of them
}