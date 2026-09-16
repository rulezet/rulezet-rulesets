rule TTP_XOR_MULT_DOSStub_0c97 {
  strings:
    $key_0c97 = { 58 ff [2] 2c e7 [2] 6b e5 [2] 2c f4 [2] 62 f8 [2] 6e f2 [2] 79 f9 [2] 62 b7 [2] 5f }

  condition:
    any of them
}