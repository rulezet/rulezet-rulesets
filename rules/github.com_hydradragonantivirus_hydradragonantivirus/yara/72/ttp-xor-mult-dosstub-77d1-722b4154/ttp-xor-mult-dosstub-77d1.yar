rule TTP_XOR_MULT_DOSStub_77d1 {
  strings:
    $key_77d1 = { 23 b9 [2] 57 a1 [2] 10 a3 [2] 57 b2 [2] 19 be [2] 15 b4 [2] 02 bf [2] 19 f1 [2] 24 }

  condition:
    any of them
}