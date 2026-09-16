rule TTP_XOR_MULT_DOSStub_0cba {
  strings:
    $key_0cba = { 58 d2 [2] 2c ca [2] 6b c8 [2] 2c d9 [2] 62 d5 [2] 6e df [2] 79 d4 [2] 62 9a [2] 5f }

  condition:
    any of them
}