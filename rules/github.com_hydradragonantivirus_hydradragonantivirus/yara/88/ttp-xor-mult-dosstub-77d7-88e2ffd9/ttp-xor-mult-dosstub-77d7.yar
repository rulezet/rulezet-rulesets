rule TTP_XOR_MULT_DOSStub_77d7 {
  strings:
    $key_77d7 = { 23 bf [2] 57 a7 [2] 10 a5 [2] 57 b4 [2] 19 b8 [2] 15 b2 [2] 02 b9 [2] 19 f7 [2] 24 }

  condition:
    any of them
}