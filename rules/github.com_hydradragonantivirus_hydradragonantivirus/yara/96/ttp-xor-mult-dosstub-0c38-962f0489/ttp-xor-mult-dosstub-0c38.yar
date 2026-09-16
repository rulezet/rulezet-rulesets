rule TTP_XOR_MULT_DOSStub_0c38 {
  strings:
    $key_0c38 = { 58 50 [2] 2c 48 [2] 6b 4a [2] 2c 5b [2] 62 57 [2] 6e 5d [2] 79 56 [2] 62 18 [2] 5f }

  condition:
    any of them
}