rule TTP_XOR_MULT_DOSStub_77d6 {
  strings:
    $key_77d6 = { 23 be [2] 57 a6 [2] 10 a4 [2] 57 b5 [2] 19 b9 [2] 15 b3 [2] 02 b8 [2] 19 f6 [2] 24 }

  condition:
    any of them
}