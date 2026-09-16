rule TTP_XOR_MULT_DOSStub_0c4f {
  strings:
    $key_0c4f = { 58 27 [2] 2c 3f [2] 6b 3d [2] 2c 2c [2] 62 20 [2] 6e 2a [2] 79 21 [2] 62 6f [2] 5f }

  condition:
    any of them
}