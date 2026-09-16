rule TTP_XOR_MULT_DOSStub_35d6 {
  strings:
    $key_35d6 = { 61 be [2] 15 a6 [2] 52 a4 [2] 15 b5 [2] 5b b9 [2] 57 b3 [2] 40 b8 [2] 5b f6 [2] 66 }

  condition:
    any of them
}