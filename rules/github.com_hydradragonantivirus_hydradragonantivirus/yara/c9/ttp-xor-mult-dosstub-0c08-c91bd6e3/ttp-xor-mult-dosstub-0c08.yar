rule TTP_XOR_MULT_DOSStub_0c08 {
  strings:
    $key_0c08 = { 58 60 [2] 2c 78 [2] 6b 7a [2] 2c 6b [2] 62 67 [2] 6e 6d [2] 79 66 [2] 62 28 [2] 5f }

  condition:
    any of them
}