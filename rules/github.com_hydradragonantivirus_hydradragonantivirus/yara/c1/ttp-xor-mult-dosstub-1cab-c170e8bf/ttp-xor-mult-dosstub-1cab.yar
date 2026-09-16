rule TTP_XOR_MULT_DOSStub_1cab {
  strings:
    $key_1cab = { 48 c3 [2] 3c db [2] 7b d9 [2] 3c c8 [2] 72 c4 [2] 7e ce [2] 69 c5 [2] 72 8b [2] 4f }

  condition:
    any of them
}