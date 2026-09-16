rule TTP_XOR_MULT_DOSStub_0cab {
  strings:
    $key_0cab = { 58 c3 [2] 2c db [2] 6b d9 [2] 2c c8 [2] 62 c4 [2] 6e ce [2] 79 c5 [2] 62 8b [2] 5f }

  condition:
    any of them
}