rule TTP_XOR_MULT_DOSStub_5981 {
  strings:
    $key_5981 = { 0d e9 [2] 79 f1 [2] 3e f3 [2] 79 e2 [2] 37 ee [2] 3b e4 [2] 2c ef [2] 37 a1 [2] 0a }

  condition:
    any of them
}