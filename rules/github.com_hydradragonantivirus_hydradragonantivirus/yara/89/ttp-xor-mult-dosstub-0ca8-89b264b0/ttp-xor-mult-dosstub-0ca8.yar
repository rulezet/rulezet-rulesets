rule TTP_XOR_MULT_DOSStub_0ca8 {
  strings:
    $key_0ca8 = { 58 c0 [2] 2c d8 [2] 6b da [2] 2c cb [2] 62 c7 [2] 6e cd [2] 79 c6 [2] 62 88 [2] 5f }

  condition:
    any of them
}