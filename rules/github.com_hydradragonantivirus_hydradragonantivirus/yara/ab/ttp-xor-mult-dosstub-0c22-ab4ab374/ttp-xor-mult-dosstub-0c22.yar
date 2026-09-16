rule TTP_XOR_MULT_DOSStub_0c22 {
  strings:
    $key_0c22 = { 58 4a [2] 2c 52 [2] 6b 50 [2] 2c 41 [2] 62 4d [2] 6e 47 [2] 79 4c [2] 62 02 [2] 5f }

  condition:
    any of them
}