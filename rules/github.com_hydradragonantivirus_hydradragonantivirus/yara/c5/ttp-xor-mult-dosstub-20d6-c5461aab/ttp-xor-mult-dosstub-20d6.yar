rule TTP_XOR_MULT_DOSStub_20d6 {
  strings:
    $key_20d6 = { 74 be [2] 00 a6 [2] 47 a4 [2] 00 b5 [2] 4e b9 [2] 42 b3 [2] 55 b8 [2] 4e f6 [2] 73 }

  condition:
    any of them
}