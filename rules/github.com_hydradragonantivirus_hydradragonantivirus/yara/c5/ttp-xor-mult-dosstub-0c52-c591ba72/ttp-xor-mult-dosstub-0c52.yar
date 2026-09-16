rule TTP_XOR_MULT_DOSStub_0c52 {
  strings:
    $key_0c52 = { 58 3a [2] 2c 22 [2] 6b 20 [2] 2c 31 [2] 62 3d [2] 6e 37 [2] 79 3c [2] 62 72 [2] 5f }

  condition:
    any of them
}