rule TTP_XOR_MULT_DOSStub_0c58 {
  strings:
    $key_0c58 = { 58 30 [2] 2c 28 [2] 6b 2a [2] 2c 3b [2] 62 37 [2] 6e 3d [2] 79 36 [2] 62 78 [2] 5f }

  condition:
    any of them
}