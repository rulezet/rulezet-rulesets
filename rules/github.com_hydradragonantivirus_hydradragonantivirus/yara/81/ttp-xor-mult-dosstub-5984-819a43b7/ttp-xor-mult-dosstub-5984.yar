rule TTP_XOR_MULT_DOSStub_5984 {
  strings:
    $key_5984 = { 0d ec [2] 79 f4 [2] 3e f6 [2] 79 e7 [2] 37 eb [2] 3b e1 [2] 2c ea [2] 37 a4 [2] 0a }

  condition:
    any of them
}